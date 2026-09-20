//! Authority-commit protocol core for Arkret bridges.
//!
//! A producer Event carries no predecessor, ordering, or basis. The
//! current governance Station accepts an Event by issuing an authority-signed
//! [`RealmCommit`] in exactly one independent Realm, Circle, or Sidecar stream.

use std::collections::BTreeMap;

use arkret::{Client, ClientRequestOptions};
use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_models_integration::{
    AppletManagedActorAuthoringBasis, AppletManagedActorAuthoringBundle,
    AppletManagedActorAuthoringRequest,
};
use arkret_wire::{
    AuthoredEvent, AuthorityBundleRequest, AuthorityCommitStatus, AuthorityHandoffRequest,
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthoritySubmitRequest, CommitStreamHead,
    CommitStreamRef, CommittedEventRef, CommittedEventResolveOutcome, CommittedEventResolveRequest,
    DetachedSignatureContext, Event, EventCommitSubmission, MlsCommitSubmission,
    MlsWelcomeDelivery, ProducerEventProof, RealmAuthorityBundle, RealmCommit, RealmStateSnapshot,
    StreamScanOutcome, StreamScanRequest,
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
pub trait GovernanceStationTransport: Send + Sync {
    async fn submit(
        &self,
        request: &AuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome>;

    async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle>;

    async fn scan_stream(&self, request: &StreamScanRequest) -> Result<StreamScanOutcome>;

    async fn resolve_committed(
        &self,
        request: &CommittedEventResolveRequest,
    ) -> Result<CommittedEventResolveOutcome>;
}

#[async_trait]
impl GovernanceStationTransport for Client {
    async fn submit(
        &self,
        request: &AuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        protocol(self.submit_to_realm_authority(request, options).await)
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

    async fn resolve_committed(
        &self,
        request: &CommittedEventResolveRequest,
    ) -> Result<CommittedEventResolveOutcome> {
        protocol(self.resolve_committed_events(request).await)
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
        self.enqueue(AuthoritySubmitRequest::Event(EventCommitSubmission {
            event: event.into_event(),
        }))
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
        let request = self.submissions[index].request.clone();
        let outcome = station.submit(&request, options).await?;
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
            || self.snapshot.authority_generation != self.authority_bundle.current_generation
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
                || tail.request.after_position != Some(head.stream_position)
            {
                return Err(BridgeProtocolError::InvalidBootstrap);
            }
            protocol(tail.outcome.validate_for_request(&tail.request))?;
            if let Some(first) = tail.outcome.commits.first()
                && (first.commit.previous_commit_ref.as_ref() != Some(&head.commit_id)
                    || first.commit.stream_position != head.stream_position.saturating_add(1))
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
        if tail.request.after_position != Some(current.stream_position) {
            return Err(BridgeProtocolError::InvalidStreamTail);
        }
        if let Some(first) = tail.outcome.commits.first()
            && first.commit.previous_commit_ref.as_ref() != Some(&current.commit_id)
        {
            return Err(BridgeProtocolError::InvalidStreamTail);
        }
        if let Some(last) = tail.outcome.commits.last() {
            self.heads.insert(
                tail.request.stream_ref.clone(),
                CommitStreamHead {
                    stream_ref: last.commit.stream_ref.clone(),
                    stream_position: last.commit.stream_position,
                    commit_id: last.commit.commit_id.clone(),
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

/// Additional verification for a complete managed-actor authoring unit.
pub trait ManagedActorProofVerifier: ProducerProofVerifier {
    fn verify_bundle_proof(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        bundle: &AppletManagedActorAuthoringBundle,
    ) -> Result<()>;
}

/// Validate that Applet-managed actor output is genuinely producer-authored.
/// A Station may authorize and commit the Events but can never produce them.
pub fn validate_managed_actor_bundle<V: ManagedActorProofVerifier>(
    request: &AppletManagedActorAuthoringRequest,
    bundle: &AppletManagedActorAuthoringBundle,
    verifier: &V,
) -> Result<()> {
    protocol(request.validate_bindings())?;
    protocol(bundle.validate_bindings(request))?;
    let applet_id = match &request.basis {
        AppletManagedActorAuthoringBasis::InstallBot(basis) => &basis.applet_id,
        AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => &basis.applet_id,
    };
    let station_id = &request.authoring_authority.service_id;
    let events = [
        &bundle.managed_actor_provision_event,
        &bundle.pcr_genesis_event,
        &bundle.accountability_grant_event,
        &bundle.profile_event,
    ];
    for event in events {
        if event.applet_id.as_ref() != Some(applet_id) {
            return Err(BridgeProtocolError::InvalidManagedActorProducer);
        }
        validate_producer_event(event, Some(station_id), verifier)?;
    }
    let bundle_controller = bundle
        .proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or(BridgeProtocolError::InvalidManagedActorProducer)?;
    let bundle_controller = protocol(arkret_wire::Did::new(bundle_controller.to_owned()))?;
    if protocol(arkret_wire::project_did_to_core_id(&bundle_controller))? == *station_id {
        return Err(BridgeProtocolError::InvalidManagedActorProducer);
    }
    verifier.verify_bundle_proof(request, bundle)
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
            refs: Vec::new(),
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
