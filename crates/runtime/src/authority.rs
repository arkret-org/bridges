//! Authority-commit protocol core for Arkret bridges.
//!
//! A producer Event carries no predecessor, ordering, or basis. The
//! current governance Station accepts an Event by issuing an authority-signed
//! [`RealmCommit`] in exactly one independent Realm, Circle, or Sidecar stream.

use std::collections::BTreeMap;

use arkret::{Client, ClientRequestOptions, VerifiedSubmission};
use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_models_collaboration::authority_commit::{
    AuthorityHandoffRequest, SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
use arkret_wire::{
    AuthoredEvent, AuthorityBundleRequest, AuthorityCommitStatus, AuthorityRejectionStatus,
    AuthoritySubmitOutcome, AuthoritySubmitRequest, CommitStreamHead, CommitStreamRef,
    CommittedEventRef, DetachedSignatureContext, DidUrl, Event, EventAdmissionSubmission,
    MlsCommitSubmission, MlsWelcomeDelivery, ProducerEventProof, RealmAuthorityBundle, RealmCommit,
    RealmStateSnapshot, StreamScanDirection, StreamScanOutcome, StreamScanRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeProtocolError {
    #[error("protocol contract violation: {0}")]
    Protocol(String),
    #[error("event is already queued")]
    DuplicateEvent,
    #[error("event is not queued")]
    UnknownEvent,
    #[error("submission already reached a terminal state")]
    TerminalSubmission,
    #[error("bootstrap package does not match the verified current authority")]
    InvalidBootstrap,
    #[error("stream tail does not continue the same-stream cursor")]
    InvalidStreamTail,
    #[error("managed actor producer proof is absent, mismatched, or Station-controlled")]
    InvalidManagedActorProducer,
}

pub type Result<T> = std::result::Result<T, BridgeProtocolError>;

fn protocol<T, E: std::fmt::Display>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|error| BridgeProtocolError::Protocol(error.to_string()))
}

/// Network boundary for the authenticated current governance Station.
#[async_trait]
#[expect(
    clippy::double_must_use,
    reason = "async-trait adds an unconditional must_use attribute to its boxed Future methods."
)]
pub trait GovernanceStationTransport: Send + Sync {
    async fn submit(
        &self,
        request: &VerifiedSubmission<AuthoritySubmitRequest>,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome>;

    async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle>;

    async fn scan_stream(&self, request: &StreamScanRequest) -> Result<StreamScanOutcome>;
}

#[async_trait]
impl GovernanceStationTransport for Client {
    async fn submit(
        &self,
        request: &VerifiedSubmission<AuthoritySubmitRequest>,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        let wire = match request.wire() {
            AuthoritySubmitRequest::Event(value) => {
                SelfAuthoritySubmitRequest::Event(value.clone())
            }
            AuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitRequest::MlsCommit(value.clone())
            }
        };
        let request = protocol(request.rebind(wire))?;
        match protocol(self.submit_to_realm_authority(&request, options).await)? {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(BridgeProtocolError::Protocol(
                "ordinary submission returned an aggregate outcome".to_owned(),
            )),
        }
    }

    async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle> {
        protocol(self.realm_authority_bundle(request).await)
    }

    async fn scan_stream(&self, request: &StreamScanRequest) -> Result<StreamScanOutcome> {
        protocol(self.scan_commit_stream(request).await)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SubmissionState {
    Queued,
    Retryable {
        reason_code: String,
    },
    Committed {
        status: AuthorityCommitStatus,
        commit: Box<RealmCommit>,
    },
    Rejected {
        reason_code: String,
    },
}

impl SubmissionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Rejected { .. })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueuedSubmission {
    pub request: AuthoritySubmitRequest,
    pub state: SubmissionState,
}

impl QueuedSubmission {
    pub fn event_id(&self) -> &EventId {
        request_event_id(&self.request)
    }
}

fn request_event_id(request: &AuthoritySubmitRequest) -> &EventId {
    match request {
        AuthoritySubmitRequest::Event(request) => &request.event.event_id,
        AuthoritySubmitRequest::MlsCommit(request) => &request.commit_event.event_id,
    }
}

/// Durable outbound intent and exact committed-reference index.
#[derive(Clone, Debug, Default)]
pub struct SubmissionQueue {
    submissions: Vec<QueuedSubmission>,
    committed: BTreeMap<EventId, CommittedEventRef>,
    installed_mls_commits: Vec<EventId>,
    welcome_deliveries: Vec<MlsWelcomeDelivery>,
}

impl SubmissionQueue {
    pub fn submissions(&self) -> &[QueuedSubmission] {
        &self.submissions
    }

    pub fn committed_ref(&self, event_id: &EventId) -> Option<&CommittedEventRef> {
        self.committed.get(event_id)
    }

    pub fn enqueue_event(&mut self, event: AuthoredEvent) -> Result<()> {
        self.enqueue(AuthoritySubmitRequest::Event(
            EventAdmissionSubmission::new(event.into_event()),
        ))
    }

    pub fn enqueue_mls_commit(&mut self, submission: MlsCommitSubmission) -> Result<()> {
        self.enqueue(AuthoritySubmitRequest::MlsCommit(submission))
    }

    fn enqueue(&mut self, request: AuthoritySubmitRequest) -> Result<()> {
        protocol(request.validate())?;
        let event_id = request_event_id(&request);
        if self
            .submissions
            .iter()
            .any(|submission| submission.event_id() == event_id)
        {
            return Err(BridgeProtocolError::DuplicateEvent);
        }
        self.submissions.push(QueuedSubmission {
            request,
            state: SubmissionState::Queued,
        });
        Ok(())
    }

    /// Submit one queued Event to the already authenticated current Station.
    pub async fn submit_one<T: GovernanceStationTransport + ?Sized>(
        &mut self,
        event_id: &EventId,
        station: &T,
        verified: &VerifiedSubmission<AuthoritySubmitRequest>,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        let index = self
            .submissions
            .iter()
            .position(|submission| submission.event_id() == event_id)
            .ok_or(BridgeProtocolError::UnknownEvent)?;
        if self.submissions[index].state.is_terminal() {
            return Err(BridgeProtocolError::TerminalSubmission);
        }
        if verified.wire() != &self.submissions[index].request {
            return Err(BridgeProtocolError::Protocol(
                "verified submission differs from the frozen queue entry".into(),
            ));
        }
        let outcome = station.submit(verified, options).await?;
        self.apply_outcome(event_id, &outcome)?;
        Ok(outcome)
    }

    pub fn apply_outcome(
        &mut self,
        event_id: &EventId,
        outcome: &AuthoritySubmitOutcome,
    ) -> Result<()> {
        let submission = self
            .submissions
            .iter_mut()
            .find(|submission| submission.event_id() == event_id)
            .ok_or(BridgeProtocolError::UnknownEvent)?;
        if submission.state.is_terminal() {
            return Err(BridgeProtocolError::TerminalSubmission);
        }
        protocol(outcome.validate_for_request(&submission.request))?;
        match outcome {
            AuthoritySubmitOutcome::Accepted { status, commit } => {
                self.committed.insert(
                    event_id.clone(),
                    CommittedEventRef {
                        event_id: event_id.clone(),
                        commit_id: commit.commit_id.clone(),
                        stream_ref: commit.stream_ref.clone(),
                        stream_position: commit.stream_position,
                    },
                );
                if let AuthoritySubmitRequest::MlsCommit(request) = &submission.request {
                    self.installed_mls_commits.push(event_id.clone());
                    self.welcome_deliveries.extend(request.welcomes.clone());
                }
                submission.state = SubmissionState::Committed {
                    status: *status,
                    commit: Box::new(commit.clone()),
                };
            }
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::RetryableUnavailable,
                reason_code,
            } => {
                submission.state = SubmissionState::Retryable {
                    reason_code: reason_code.clone(),
                };
            }
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::Rejected,
                reason_code,
            } => {
                submission.state = SubmissionState::Rejected {
                    reason_code: reason_code.clone(),
                };
            }
        }
        Ok(())
    }

    pub fn mls_commit_is_installed(&self, event_id: &EventId) -> bool {
        self.installed_mls_commits.contains(event_id)
    }

    pub fn take_welcome_deliveries(&mut self, event_id: &EventId) -> Vec<MlsWelcomeDelivery> {
        let mut selected = Vec::new();
        self.welcome_deliveries.retain(|delivery| {
            if &delivery.commit_event_ref == event_id {
                selected.push(delivery.clone());
                false
            } else {
                true
            }
        });
        selected
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StreamTail {
    pub request: StreamScanRequest,
    pub outcome: StreamScanOutcome,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CurrentAuthority {
    pub realm_id: RealmId,
    pub generation: u64,
    pub service_id: DidCoreId,
    pub route_record: Value,
}

pub trait AuthorityMaterialVerifier {
    fn verify_authority_bundle(&self, bundle: &RealmAuthorityBundle) -> Result<()>;
    fn verify_snapshot(
        &self,
        snapshot: &RealmStateSnapshot,
        current_service_id: &DidCoreId,
    ) -> Result<()>;
    fn verify_handoff(&self, request: &AuthorityHandoffRequest) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct JoinBootstrap {
    pub authority_bundle: RealmAuthorityBundle,
    pub snapshot: RealmStateSnapshot,
    pub stream_tails: Vec<StreamTail>,
}

impl JoinBootstrap {
    pub fn validate<V: AuthorityMaterialVerifier>(
        &self,
        authority_request: &AuthorityBundleRequest,
        now: DateTime<Utc>,
        verifier: &V,
    ) -> Result<CurrentAuthority> {
        protocol(
            self.authority_bundle
                .validate_for_request(authority_request, now),
        )?;
        verifier.verify_authority_bundle(&self.authority_bundle)?;
        let heads = &self.snapshot.visible_stream_heads;
        if self.snapshot.realm_id != self.authority_bundle.realm_id
            || self.snapshot.governance_generation != self.authority_bundle.current_generation
            || self.snapshot.signature.context != DetachedSignatureContext::RealmSnapshot
            || heads.is_empty()
            || !heads
                .windows(2)
                .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
            || heads
                .iter()
                .any(|head| head.stream_ref.realm_id() != &self.snapshot.realm_id)
            || self.stream_tails.len() != heads.len()
        {
            return Err(BridgeProtocolError::InvalidBootstrap);
        }
        verifier.verify_snapshot(&self.snapshot, &self.authority_bundle.current_service_id)?;
        for (head, tail) in heads.iter().zip(&self.stream_tails) {
            if tail.request.realm_id != self.snapshot.realm_id
                || tail.request.stream_ref != head.stream_ref
                || tail.request.direction != StreamScanDirection::After(Some(head.stream_position))
            {
                return Err(BridgeProtocolError::InvalidBootstrap);
            }
            protocol(tail.outcome.validate_for_request(&tail.request))?;
            if let Some(first) = tail.outcome.committed_events.first()
                && (first.commit().previous_commit_ref.as_ref() != Some(&head.commit_id)
                    || first.commit().stream_position != head.stream_position.saturating_add(1))
            {
                return Err(BridgeProtocolError::InvalidBootstrap);
            }
        }
        Ok(CurrentAuthority {
            realm_id: self.authority_bundle.realm_id.clone(),
            generation: self.authority_bundle.current_generation,
            service_id: self.authority_bundle.current_service_id.clone(),
            route_record: self.authority_bundle.current_route_record.clone(),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamCursorBook {
    heads: BTreeMap<CommitStreamRef, CommitStreamHead>,
}

impl StreamCursorBook {
    pub fn from_snapshot(snapshot: &RealmStateSnapshot) -> Result<Self> {
        let mut heads = BTreeMap::new();
        for head in &snapshot.visible_stream_heads {
            if head.stream_ref.realm_id() != &snapshot.realm_id
                || heads
                    .insert(head.stream_ref.clone(), head.clone())
                    .is_some()
            {
                return Err(BridgeProtocolError::InvalidBootstrap);
            }
        }
        Ok(Self { heads })
    }

    pub fn head(&self, stream_ref: &CommitStreamRef) -> Option<&CommitStreamHead> {
        self.heads.get(stream_ref)
    }

    pub fn apply_tail(&mut self, tail: &StreamTail) -> Result<()> {
        protocol(tail.outcome.validate_for_request(&tail.request))?;
        let current = self
            .heads
            .get(&tail.request.stream_ref)
            .ok_or(BridgeProtocolError::InvalidStreamTail)?;
        if tail.request.direction != StreamScanDirection::After(Some(current.stream_position)) {
            return Err(BridgeProtocolError::InvalidStreamTail);
        }
        if let Some(first) = tail.outcome.committed_events.first()
            && first.commit().previous_commit_ref.as_ref() != Some(&current.commit_id)
        {
            return Err(BridgeProtocolError::InvalidStreamTail);
        }
        if let Some(last) = tail.outcome.committed_events.last() {
            self.heads.insert(
                tail.request.stream_ref.clone(),
                CommitStreamHead {
                    stream_ref: last.commit().stream_ref.clone(),
                    stream_position: last.commit().stream_position,
                    commit_id: last.commit().commit_id.clone(),
                },
            );
        }
        Ok(())
    }
}

pub fn validate_handoff<V: AuthorityMaterialVerifier>(
    request: &AuthorityHandoffRequest,
    verifier: &V,
) -> Result<()> {
    protocol(request.validate_shape())?;
    verifier.verify_handoff(request)
}

/// Cryptographic proof verifier supplied by the bridge's producer-key backend.
pub trait ProducerProofVerifier {
    fn verify_event_proof(&self, event: &Event, proof: &ProducerEventProof) -> Result<()>;
}

/// Resolver-free verifier for the exact Applet Service signer held by this
/// bridge process. Realm creation uses this Service producer; subsequent
/// Realm actor writes require their own accepted controller or Device key.
#[derive(Clone)]
pub struct LocalServiceManagedActorProofVerifier {
    service_id: DidCoreId,
    verification_method: DidUrl,
    public_key: PublicKeyMaterial,
}

impl LocalServiceManagedActorProofVerifier {
    pub fn new(
        service_id: DidCoreId,
        verification_method: DidUrl,
        public_key: PublicKeyMaterial,
    ) -> Result<Self> {
        let controller = protocol(arkret::verification_method_did(
            verification_method.as_str(),
        ))?;
        if protocol(arkret_wire::project_did_to_core_id(&controller))? != service_id {
            return Err(BridgeProtocolError::InvalidManagedActorProducer);
        }
        public_key
            .ed25519_bytes()
            .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?;
        Ok(Self {
            service_id,
            verification_method,
            public_key,
        })
    }
}

impl ProducerProofVerifier for LocalServiceManagedActorProofVerifier {
    fn verify_event_proof(&self, event: &Event, proof: &ProducerEventProof) -> Result<()> {
        if proof.verification_method != self.verification_method
            || event.actual_signer() != &arkret::ActorId::service(self.service_id.clone())
        {
            return Err(BridgeProtocolError::InvalidManagedActorProducer);
        }
        let bytes = arkret_canonical::canonical_json_bytes(&protocol(event.digest_payload())?)
            .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?;
        verify_ed25519_detached_jws_proof(proof, &bytes, &event.actor_id, &self.public_key)
            .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))
    }
}

/// Verify an accepted delivery with actual producer and governance keys. The
/// host supplies these from its installed trust material, never from the pair.
pub fn validate_applet_committed_delivery(
    pair: &arkret_models_integration::AppletCommittedEvent,
    digest_suite: arkret_canonical::DigestSuite,
    producer_key: &PublicKeyMaterial,
    governance_key: &PublicKeyMaterial,
) -> Result<CommittedEventRef> {
    protocol(pair.validate_shape())?;
    protocol(pair.commit.verify_commit_id_matches_content())?;
    protocol(
        pair.event
            .verify_event_id_matches_content_with_digest_suite(digest_suite),
    )?;
    let proof = pair.event.producer_proof.as_ref().ok_or_else(|| {
        BridgeProtocolError::Protocol("accepted delivery has no original producer proof".into())
    })?;
    let producer_did = protocol(arkret::verification_method_did(
        proof.verification_method.as_str(),
    ))?;
    let producer_id = protocol(arkret_wire::project_did_to_core_id(&producer_did))?;
    if let Some(producer) = protocol(pair.event.account_device_producer())? {
        let evidence = pair.producer_device_evidence.as_ref().ok_or_else(|| {
            BridgeProtocolError::Protocol("Account Device delivery lacks original evidence".into())
        })?;
        protocol(arkret::identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
            evidence,
            &producer.account_id,
            &producer.device_id,
        ))?;
        let attestation = &evidence.device_projection_attestation.attestation;
        let window = &attestation.authorization_window;
        let covers = |at| at >= window.not_before && window.expires_at.is_none_or(|end| at < end);
        if !attestation.device_status.is_active()
            || attestation.attested_at > pair.commit.committed_at
            || pair.commit.committed_at >= attestation.expires_at
            || !covers(pair.event.created_at)
            || !covers(proof.created_at)
            || !covers(pair.commit.committed_at)
        {
            return Err(BridgeProtocolError::Protocol(
                "original Device authorization does not cover the accepted Event and Commit".into(),
            ));
        }
        let multibase = attestation
            .device_signing_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| {
                BridgeProtocolError::Protocol("original Device signing key is not did:key".into())
            })?;
        let actual = PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        };
        if actual
            .ed25519_bytes()
            .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?
            != producer_key
                .ed25519_bytes()
                .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?
        {
            return Err(BridgeProtocolError::Protocol(
                "Device producer key differs from its original authorized key".into(),
            ));
        }
    }
    if &producer_id
        != pair
            .event
            .executed_by
            .as_ref()
            .unwrap_or(&pair.event.actor_id)
            .signing_principal_id()
    {
        return Err(BridgeProtocolError::Protocol(
            "accepted delivery producer is bound to another actor".into(),
        ));
    }
    let payload = protocol(pair.event.digest_payload())?;
    let bytes = protocol(arkret_canonical::canonical_json_bytes(&payload))?;
    protocol(verify_ed25519_detached_jws_proof(
        proof,
        &bytes,
        &pair.event.actor_id,
        producer_key,
    ))?;
    let unsigned = protocol(arkret_canonical::unsigned_value(
        &pair.commit,
        &["signature"],
    ))?;
    protocol(
        arkret_signatures::detached_object::verify_detached_object_signature(
            &pair.commit.signature,
            &unsigned,
            DetachedSignatureContext::RealmCommit,
            governance_key,
        ),
    )?;
    Ok(CommittedEventRef {
        event_id: pair.event.event_id.clone(),
        commit_id: pair.commit.commit_id.clone(),
        stream_ref: pair.commit.stream_ref.clone(),
        stream_position: pair.commit.stream_position,
    })
}

/// Resolve the immutable original Device key from its self-certifying DID.
/// The accepted governance Commit remains mandatory: did:key possession alone
/// does not establish Account membership or authorize the submitted Event.
pub fn committed_delivery_device_key(method: &arkret::DidUrl) -> Result<Option<PublicKeyMaterial>> {
    use arkret::DidResolver as _;
    let did = protocol(arkret::verification_method_did(method.as_str()))?;
    if did.method() != "key" {
        return Ok(None);
    }
    let resolved = arkret::DidKeyResolver::new()
        .resolve_did(&did)
        .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?;
    let key = arkret::identity::jws::resolve_ed25519_pubkey_from_document(
        &resolved.document,
        method.as_str(),
    )
    .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?;
    Ok(Some(PublicKeyMaterial::Ed25519Raw {
        bytes: key.as_bytes().to_vec(),
    }))
}

pub fn validate_producer_event<V: ProducerProofVerifier + ?Sized>(
    event: &Event,
    forbidden_station_id: Option<&DidCoreId>,
    verifier: &V,
) -> Result<()> {
    protocol(event.validate_for_submit_structural())?;
    let Some(proof) = event.producer_proof.as_ref() else {
        return Err(BridgeProtocolError::InvalidManagedActorProducer);
    };
    let controller = proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or(BridgeProtocolError::InvalidManagedActorProducer)?;
    let controller = protocol(arkret_wire::Did::new(controller.to_owned()))?;
    let producer_id = protocol(arkret_wire::project_did_to_core_id(&controller))?;
    if &producer_id != event.actor_id.signing_principal_id()
        || forbidden_station_id == Some(&producer_id)
    {
        return Err(BridgeProtocolError::InvalidManagedActorProducer);
    }
    verifier.verify_event_proof(event, proof)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_canonical::DigestSuite;
    use arkret_identifiers::{CircleId, EventId, RealmCommitId, RealmId, SidecarId};
    use arkret_signatures::{
        Ed25519DetachedJwsSigner, PublicKeyMaterial, SignEventOptions, sign_event,
        verify_ed25519_detached_jws_proof,
    };
    use arkret_wire::{ActorId, ScopeRef};
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn event_id(byte: u8) -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [byte; 32])
    }

    struct CryptoProofVerifier(PublicKeyMaterial);

    impl ProducerProofVerifier for CryptoProofVerifier {
        fn verify_event_proof(&self, event: &Event, proof: &ProducerEventProof) -> Result<()> {
            let bytes = arkret_canonical::canonical_json_bytes(
                &event
                    .digest_payload()
                    .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?,
            )
            .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))?;
            verify_ed25519_detached_jws_proof(proof, &bytes, &event.actor_id, &self.0)
                .map_err(|error| BridgeProtocolError::Protocol(error.to_string()))
        }
    }

    fn signed_event(
        controller_did: &str,
        controller_core_id: &str,
        seed: [u8; 32],
    ) -> (Event, CryptoProofVerifier) {
        let placeholder = event_id(seed[0]);
        let realm_id = RealmId::from_event_id(&placeholder);
        let event = Event {
            event_id: placeholder,
            kind: "ak.message.create".into(),
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm { realm_id },
            actor_id: ActorId::service(DidCoreId::new(controller_core_id).unwrap()),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
            semantic_refs: Vec::new(),
            payload: BTreeMap::from([("body".to_owned(), json!("hello"))]),
            producer_proof: None,
        };
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
        let signer =
            Ed25519DetachedJwsSigner::from_seed(seed, format!("{controller_did}#producer-key"));
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };
        sign_event(&mut authored, &signer, SignEventOptions::new()).unwrap();
        (authored.into_event(), CryptoProofVerifier(public_key))
    }

    #[test]
    fn committed_delivery_verifies_both_signatures_and_returns_exact_coordinates() {
        use arkret_signatures::detached_object::sign_detached_object;
        let (event, producer) = signed_event(
            "did:web:producer.example",
            "ak:did_core:web:producer.example",
            [9; 32],
        );
        let key = arkret_test_kit::keys::development_signing_key("did:web:station.example");
        let public = PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        };
        let method = DidUrl::new("did:web:station.example#commit").unwrap();
        let at = event.created_at;
        let placeholder = sign_detached_object(
            &json!({}),
            DetachedSignatureContext::RealmCommit,
            method.clone(),
            at,
            &key,
        )
        .unwrap();
        let mut commit = RealmCommit {
            commit_id: RealmCommitId::from_digest([0x85; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: 3,
            previous_commit_ref: Some(RealmCommitId::from_digest([0x84; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 1,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id(
                0x83,
            )),
            committed_at: at,
            producer_signer_fact_digest: None,
            signature: placeholder,
        };
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(
                &arkret_canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap(),
            )
            .unwrap(),
        ));
        commit.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            method,
            at,
            &key,
        )
        .unwrap();
        let pair = arkret_models_integration::AppletCommittedEvent {
            commit,
            event,
            producer_device_evidence: None,
        };
        let reference =
            validate_applet_committed_delivery(&pair, DigestSuite::Sha256, &producer.0, &public)
                .unwrap();
        assert_eq!(reference.event_id, pair.event.event_id);
        assert_eq!(reference.commit_id, pair.commit.commit_id);
        assert_eq!(reference.stream_position, 3);
        let mut wrong_event = pair.clone();
        wrong_event
            .event
            .payload
            .insert("body".into(), json!("changed"));
        assert!(
            validate_applet_committed_delivery(
                &wrong_event,
                DigestSuite::Sha256,
                &producer.0,
                &public
            )
            .is_err()
        );
        let mut wrong_commit = pair.clone();
        wrong_commit.commit.stream_position += 1;
        assert!(
            validate_applet_committed_delivery(
                &wrong_commit,
                DigestSuite::Sha256,
                &producer.0,
                &public
            )
            .is_err()
        );
        assert!(
            validate_applet_committed_delivery(&pair, DigestSuite::Sha256, &public, &public)
                .is_err()
        );
        assert!(
            validate_applet_committed_delivery(
                &pair,
                DigestSuite::Sha256,
                &producer.0,
                &producer.0
            )
            .is_err()
        );
        // Possession and a Station Commit alone cannot prove Account Device
        // authorization: the exact original signer evidence remains mandatory.
        let device_seed = [0x31; 32];
        let device_key =
            Ed25519DetachedJwsSigner::from_seed(device_seed, "did:web:device.example#key");
        let multibase =
            arkret::ed25519_pubkey_to_did_key_multibase(&device_key.verifying_key().to_bytes());
        let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
        let mut event = pair.event.clone();
        event.actor_id = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:user.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        event.producer_proof = None;
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
        let signer = Ed25519DetachedJwsSigner::from_seed(
            device_seed,
            "did:web:user.example#ak:device:0196419b-0000-7000-8000-000000000001",
        );
        sign_event(&mut authored, &signer, SignEventOptions::new()).unwrap();
        let event = authored.into_event();
        let mut commit = pair.commit.clone();
        commit.event_ref = event.event_id.clone();
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(
                &arkret_canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap(),
            )
            .unwrap(),
        ));
        commit.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            commit.signature.verification_method.clone(),
            at,
            &key,
        )
        .unwrap();
        let device_pair = arkret_models_integration::AppletCommittedEvent {
            event,
            commit,
            producer_device_evidence: None,
        };
        let actual_device = committed_delivery_device_key(&method).unwrap().unwrap();
        assert!(
            validate_applet_committed_delivery(
                &device_pair,
                DigestSuite::Sha256,
                &actual_device,
                &public
            )
            .is_err()
        );
        assert!(
            validate_applet_committed_delivery(
                &device_pair,
                DigestSuite::Sha256,
                &producer.0,
                &public
            )
            .is_err()
        );
    }

    #[test]
    fn original_device_evidence_verifies_history_and_commit_time_window() {
        use arkret::identity::account_device_signer_evidence::verify_current_account_device_signer_evidence;
        use arkret_signatures::detached_object::sign_detached_object;
        use arkret_signatures::device_projection::sign_device_projection_attestation;
        use arkret_signatures::webvh::{
            ServiceRegistrationInceptionInput, prepare_service_registration_inception,
        };
        use rand_chacha::ChaCha20Rng;
        use rand_chacha::rand_core::SeedableRng;

        let registered_at = Utc.with_ymd_and_hms(2026, 9, 24, 0, 0, 0).unwrap();
        let mut rng = ChaCha20Rng::from_seed([74; 32]);
        let registration = arkret::ServiceRegistrationKey::new(
            arkret::ServiceKind::Station,
            arkret::CanonicalServiceUrl::new("https://device-origin.example/").unwrap(),
        )
        .unwrap();
        let inception = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse().unwrap(),
                registration_key: &registration,
                also_known_as: &[],
                version_time: registered_at,
                did_key_fragment: None,
            },
        )
        .unwrap();
        let station_did = arkret::Did::new(inception.did.clone()).unwrap();
        let station_id = arkret::project_did_to_core_id(&station_did).unwrap();
        let station_method = DidUrl::new(inception.did_key_id.clone()).unwrap();
        let station_key = ed25519_dalek::SigningKey::from_bytes(&inception.did_key_seed);
        let station_public = PublicKeyMaterial::Ed25519Raw {
            bytes: station_key.verifying_key().to_bytes().to_vec(),
        };
        let service_resolution = arkret::identity::build_authenticated_webvh_service_resolution(
            station_id.clone(),
            "station".into(),
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
            vec![inception.log_entry.clone()],
            vec![],
            registered_at + chrono::Duration::seconds(10),
        )
        .unwrap();
        let account = arkret::AccountId::new(
            DidCoreId::new("ak:did_core:web:device-owner.example").unwrap(),
            station_id,
        );
        let device_id =
            arkret::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let signer = Ed25519DetachedJwsSigner::from_seed(
            [0x31; 32],
            format!("did:web:device-owner.example#{device_id}"),
        );
        let producer_public = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };
        let at = registered_at + chrono::Duration::seconds(5);
        let realm_id = RealmId::from_event_id(&event_id(0x95));
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            ActorId::account(account.clone()),
            json!({"body":"original"}),
            at,
        )
        .unwrap();
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
        sign_event(
            &mut authored,
            &signer,
            SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let event = authored.into_event();
        let committed_at = registered_at + chrono::Duration::seconds(30);
        let core = arkret::DeviceProjectionAttestationCore {
            account_id: account.clone(),
            device_id: device_id.clone(),
            device_signing_key_did: arkret::DidKey::new(format!(
                "did:key:{}",
                arkret::ed25519_pubkey_to_did_key_multibase(&signer.verifying_key().to_bytes())
            ))
            .unwrap(),
            hpke_key: arkret::NonEmptyString::new("fixture-hpke-key").unwrap(),
            device_authorize_event_id: event_id(0x96),
            authorized_generation_ref: 1,
            device_status: arkret::DeviceStatus::Active,
            authorization_window: arkret::DeviceAuthorizationWindow {
                not_before: registered_at,
                expires_at: None,
            },
            attested_at: registered_at + chrono::Duration::seconds(10),
            expires_at: registered_at + chrono::Duration::minutes(5),
        };
        let evidence = arkret::AccountDeviceSignerEvidence {
            device_projection_attestation: sign_device_projection_attestation(
                core.clone(),
                station_method.clone(),
                &station_key,
            )
            .unwrap(),
            service_resolution,
        };
        let mut commit = RealmCommit {
            commit_id: RealmCommitId::from_digest([0; 32]),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: 1,
            previous_commit_ref: Some(RealmCommitId::from_digest([0x94; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 1,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id(
                0x95,
            )),
            committed_at,
            producer_signer_fact_digest: None,
            signature: sign_detached_object(
                &json!({}),
                DetachedSignatureContext::RealmCommit,
                station_method.clone(),
                committed_at,
                &station_key,
            )
            .unwrap(),
        };
        commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(
                &arkret_canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap(),
            )
            .unwrap(),
        ));
        commit.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            station_method.clone(),
            committed_at,
            &station_key,
        )
        .unwrap();
        let pair = arkret_models_integration::AppletCommittedEvent {
            event,
            commit,
            producer_device_evidence: Some(evidence.clone()),
        };
        assert!(
            verify_current_account_device_signer_evidence(
                &evidence,
                &account,
                &device_id,
                core.expires_at,
            )
            .is_err()
        );
        validate_applet_committed_delivery(
            &pair,
            DigestSuite::Sha256,
            &producer_public,
            &station_public,
        )
        .expect("the original accepted Device evidence must verify after cache expiry");

        // Re-sign the original projection so rejection is caused by the
        // Commit's authorization time, rather than a broken signature.
        let mut expired_at_commit = pair.clone();
        let mut expired_core = core.clone();
        expired_core.authorization_window.expires_at =
            Some(registered_at + chrono::Duration::seconds(20));
        expired_core.expires_at = registered_at + chrono::Duration::seconds(20);
        expired_at_commit
            .producer_device_evidence
            .as_mut()
            .unwrap()
            .device_projection_attestation =
            sign_device_projection_attestation(expired_core, station_method.clone(), &station_key)
                .unwrap();
        let error = validate_applet_committed_delivery(
            &expired_at_commit,
            DigestSuite::Sha256,
            &producer_public,
            &station_public,
        )
        .unwrap_err();
        assert!(error.to_string().contains("authorization"));

        let mut expired_proof_at_commit = pair.clone();
        let mut expired_proof_core = core.clone();
        expired_proof_core.expires_at = registered_at + chrono::Duration::seconds(12);
        expired_proof_at_commit
            .producer_device_evidence
            .as_mut()
            .unwrap()
            .device_projection_attestation = sign_device_projection_attestation(
            expired_proof_core,
            station_method.clone(),
            &station_key,
        )
        .unwrap();
        assert!(
            validate_applet_committed_delivery(
                &expired_proof_at_commit,
                DigestSuite::Sha256,
                &producer_public,
                &station_public,
            )
            .is_err()
        );

        let mut future_projection = pair.clone();
        let mut future_core = core;
        future_core.attested_at = committed_at + chrono::Duration::seconds(1);
        future_projection
            .producer_device_evidence
            .as_mut()
            .unwrap()
            .device_projection_attestation =
            sign_device_projection_attestation(future_core, station_method, &station_key).unwrap();
        assert!(
            validate_applet_committed_delivery(
                &future_projection,
                DigestSuite::Sha256,
                &producer_public,
                &station_public,
            )
            .is_err()
        );
        let mut tampered = pair.clone();
        tampered
            .producer_device_evidence
            .as_mut()
            .unwrap()
            .device_projection_attestation
            .attestation
            .hpke_key = arkret::NonEmptyString::new("changed-after-signing").unwrap();
        assert!(
            validate_applet_committed_delivery(
                &tampered,
                DigestSuite::Sha256,
                &producer_public,
                &station_public,
            )
            .is_err()
        );
        let mut current_revoked = pair.clone();
        current_revoked
            .producer_device_evidence
            .as_mut()
            .unwrap()
            .device_projection_attestation
            .attestation
            .device_status = arkret::DeviceStatus::Revoked;
        assert!(
            validate_applet_committed_delivery(
                &current_revoked,
                DigestSuite::Sha256,
                &producer_public,
                &station_public,
            )
            .is_err()
        );
        validate_applet_committed_delivery(
            &pair,
            DigestSuite::Sha256,
            &producer_public,
            &station_public,
        )
        .expect("the original accepted Device evidence must verify after cache expiry");
    }

    #[test]
    fn commit_streams_are_independent_keys() {
        let realm_id = RealmId::from_event_id(&event_id(1));
        let streams = [
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: CircleId::from_event_id(&event_id(2)),
            },
            CommitStreamRef::Sidecar {
                realm_id,
                sidecar_id: SidecarId::from_event_id(&event_id(3)),
            },
        ];
        assert_eq!(
            streams
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn cursor_book_does_not_merge_stream_positions() {
        let realm_id = RealmId::from_event_id(&event_id(4));
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let circle_stream = CommitStreamRef::Circle {
            realm_id,
            circle_id: CircleId::from_event_id(&event_id(5)),
        };
        let book = StreamCursorBook {
            heads: BTreeMap::from([
                (
                    realm_stream.clone(),
                    CommitStreamHead {
                        stream_ref: realm_stream.clone(),
                        stream_position: 3,
                        commit_id: RealmCommitId::from_digest([3; 32]),
                    },
                ),
                (
                    circle_stream.clone(),
                    CommitStreamHead {
                        stream_ref: circle_stream.clone(),
                        stream_position: 29,
                        commit_id: RealmCommitId::from_digest([29; 32]),
                    },
                ),
            ]),
        };
        assert_eq!(
            book.head(&realm_stream).map(|head| head.stream_position),
            Some(3)
        );
        assert_eq!(
            book.head(&circle_stream).map(|head| head.stream_position),
            Some(29)
        );
    }

    #[test]
    fn retryable_is_not_terminal() {
        assert!(
            !SubmissionState::Retryable {
                reason_code: "station_unavailable".to_owned(),
            }
            .is_terminal()
        );
    }

    #[test]
    fn station_cannot_substitute_for_the_event_producer() {
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let (producer_event, producer_verifier) = signed_event(
            "did:web:producer.example",
            "ak:did_core:web:producer.example",
            [9; 32],
        );
        validate_producer_event(&producer_event, Some(&station_id), &producer_verifier).unwrap();

        let (station_event, station_verifier) = signed_event(
            "did:web:station.example",
            "ak:did_core:web:station.example",
            [10; 32],
        );
        assert_eq!(
            validate_producer_event(&station_event, Some(&station_id), &station_verifier),
            Err(BridgeProtocolError::InvalidManagedActorProducer)
        );
    }
}
