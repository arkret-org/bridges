//! Indexed durable authoring for authority-commit publication.
//!
//! The journal keeps exactly one frozen, producer-signed Event per stable
//! upstream operation id, plus the exact [`CommittedEventRef`] the current
//! governance Station returned for it. It carries no predecessor, position,
//! or basis: Event order is fixed by the Station's `RealmCommit` in one
//! independent stream and is never reconstructed from producer-side state.
use std::collections::BTreeMap;
use std::sync::Arc;

use arkret::{ActorId, AppletId, AuthoredEvent, EventIntent, RealmId};
use arkret_identifiers::DidCoreId;
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, AppletInstallRequestBody,
    AppletManagedActorAuthoringBasis, AppletManagedActorCommittedRequest,
    AppletManagedActorProvisionPayload, AppletManagedActorRole,
};
use arkret_wire::{
    AuthorityCommitStatus, AuthorityRejectionStatus, AuthoritySubmitOutcome, CommitStreamRef,
    CommittedEventRef, Hash, ScopeRef,
};
use serde::{Deserialize, Serialize};

use crate::{BridgeError, Result};

/// Atomic indexed host storage. Returned reads and successful writes must be durable.
/// File deployments have one process owner; SQL deployments support concurrent processes.
pub trait AuthoringStore: Send + Sync + 'static {
    fn load(&self, key: &str) -> Result<Option<String>>;
    fn compare_exchange_batch(
        &self,
        expected: &[(String, Option<String>)],
        writes: &[(String, Option<String>)],
    ) -> Result<bool>;
    fn entries_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>>;
}

#[derive(Clone)]
pub struct AuthoringJournal {
    pub(crate) store: Arc<dyn AuthoringStore>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedAuthoringIdentity {
    pub applet_id: AppletId,
    pub actor_id: ActorId,
    pub effective_scope: ScopeRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedAuthoringInstall {
    Installed,
    ExactReplay,
}

/// One frozen publication. `intent` retains the producer-selected content so a
/// retry under the same operation id can be proven to carry identical content
/// before the exact signed bytes are sent again.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationRecord {
    pub intent: EventIntent,
    pub authored: AuthoredEvent,
    /// Terminal or retryable Station answer; stored in the atomic result row.
    #[serde(skip)]
    pub outcome: Option<AuthoritySubmitOutcome>,
    /// Exact committed reference for an accepted publication.
    #[serde(skip)]
    pub committed: Option<CommittedEventRef>,
    #[serde(skip)]
    pub result_raw: Option<String>,
    #[serde(skip)]
    pub observation_count: u64,
}

/// One answer observed from one governance Station for this publication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StationObservation {
    pub station: DidCoreId,
    pub outcome: AuthoritySubmitOutcome,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedResult {
    outcome: Option<AuthoritySubmitOutcome>,
    committed: Option<CommittedEventRef>,
    observation_count: u64,
}

/// Journal partition. It names where a publication is stored, never an order:
/// two publications in the same partition have no relative position.
pub(crate) fn scope_key(realm: &RealmId, actor: &ActorId) -> Result<String> {
    Ok(serde_json::to_string(&(realm, actor))?)
}

fn operation_key(scope: &str, operation: &str) -> Result<String> {
    Ok(format!(
        "operation/{}",
        serde_json::to_string(&(scope, operation))?
    ))
}

fn result_key(scope: &str, operation: &str) -> Result<String> {
    Ok(format!(
        "result/{}",
        serde_json::to_string(&(scope, operation))?
    ))
}

fn pending_key(scope: &str, operation: &str) -> Result<String> {
    Ok(format!(
        "pending/{}",
        serde_json::to_string(&(scope, operation))?
    ))
}

fn event_key(event: &arkret::EventId) -> String {
    format!("event/{event}")
}

fn managed_authoring_current_key(identity: &ManagedAuthoringIdentity) -> Result<String> {
    Ok(format!(
        "managed-authoring/current/{}",
        serde_json::to_string(identity)?
    ))
}

fn managed_authoring_completion_key(
    identity: &ManagedAuthoringIdentity,
    request_digest: &Hash,
) -> Result<String> {
    Ok(format!(
        "managed-authoring/completion/{}",
        serde_json::to_string(&(identity, request_digest))?
    ))
}

fn managed_authoring_preparation_key(request_digest: &Hash) -> String {
    format!("managed-authoring/prepared/{request_digest}")
}

fn managed_authoring_request(
    committed_request: &AppletManagedActorCommittedRequest,
) -> &arkret_models_integration::AppletManagedActorAuthoringRequest {
    match committed_request {
        AppletManagedActorCommittedRequest::Install(install) => install.authoring_request(),
        AppletManagedActorCommittedRequest::Ghost(ghost) => &ghost.authoring_request,
    }
}

fn realm_from_scope(scope: &ScopeRef) -> Option<&RealmId> {
    match scope {
        ScopeRef::Realm { realm_id }
        | ScopeRef::Circle { realm_id, .. }
        | ScopeRef::Sidecar { realm_id, .. } => Some(realm_id),
        _ => None,
    }
}

fn provision_payload(
    event: &arkret::Event,
) -> std::result::Result<AppletManagedActorProvisionPayload, String> {
    if event.kind != "ak.applet.managed_actor.provision" {
        return Err("authoring completion carries the wrong managed Actor provision Event".into());
    }
    let payload: AppletManagedActorProvisionPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    payload.validate().map_err(|error| error.to_string())?;
    Ok(payload)
}

/// Validate the complete Station-delivered authoring result and derive its one
/// durable installation identity. This composes SDK-owned closed carriers; it
/// does not infer authority from transport reachability or invent another
/// proof format.
pub(crate) fn validate_managed_authoring_completion(
    body: &AppletAuthoringTransactionRequestBody,
    authenticated_source_id: &DidCoreId,
    expected_applet_id: &AppletId,
    expected_service_id: &DidCoreId,
) -> std::result::Result<ManagedAuthoringIdentity, String> {
    if &body.source_id != authenticated_source_id {
        return Err("authoring completion source differs from the authenticated Station".into());
    }
    if &body.applet_id != expected_applet_id {
        return Err("authoring completion names a different Applet".into());
    }
    body.authoring_context
        .validate()
        .map_err(|error| error.to_string())?;

    let (request, bundle, actor_id, effective_scope) = match &body
        .authoring_context
        .committed_request
    {
        AppletManagedActorCommittedRequest::Install(install) => {
            let request = install.authoring_request();
            let basis = request.basis.install().ok_or_else(|| {
                "install completion carries a non-install authoring basis".to_owned()
            })?;
            let realm_id = realm_from_scope(&basis.effective_scope)
                .ok_or_else(|| "install completion has no executable Realm scope".to_owned())?;
            if install.applet_package().applet_id != basis.applet_id
                || install.applet_package().service_id != basis.service_id
            {
                return Err("install completion package differs from its authoring basis".into());
            }
            match &**install {
                AppletInstallRequestBody::Create(create) => {
                    let payload = provision_payload(
                        &create.managed_actor_bundle.managed_actor_provision_event,
                    )?;
                    if payload.applet_id != basis.applet_id
                        || payload.service_id != basis.service_id
                        || payload.actor_role != AppletManagedActorRole::Bot
                        || payload.external_ref.is_some()
                        || create
                            .managed_actor_bundle
                            .managed_actor_provision_event
                            .realm_id
                            != *realm_id
                    {
                        return Err("install completion managed Actor payload is misbound".into());
                    }
                    (
                        request,
                        Some(&create.managed_actor_bundle),
                        payload.actor_id,
                        basis.effective_scope.clone(),
                    )
                }
                AppletInstallRequestBody::Reuse(reuse) => {
                    if reuse
                        .reuse_existing_managed_actor
                        .initial_package_bot_actor_id
                        != install.applet_package().bot_actor_id
                    {
                        return Err(
                            "reused managed Actor differs from the original package Bot".into()
                        );
                    }
                    (
                        request,
                        None,
                        reuse.reuse_existing_managed_actor.actor_id.clone(),
                        basis.effective_scope.clone(),
                    )
                }
            }
        }
        AppletManagedActorCommittedRequest::Ghost(ghost) => {
            let request = &ghost.authoring_request;
            let basis = request
                .basis
                .ghost()
                .ok_or_else(|| "Ghost completion carries a non-Ghost authoring basis".to_owned())?;
            let payload = ghost
                .managed_actor_provision_payload()
                .map_err(|error| error.to_string())?;
            payload.validate().map_err(|error| error.to_string())?;
            if ghost
                .managed_actor_bundle
                .managed_actor_provision_event
                .kind
                != "ak.applet.managed_actor.provision"
                || payload.applet_id != basis.applet_id
                || payload.service_id != basis.service_id
                || payload.actor_role != AppletManagedActorRole::Ghost
                || payload.external_ref.as_ref() != Some(&basis.external_ref)
                || ghost
                    .managed_actor_bundle
                    .managed_actor_provision_event
                    .realm_id
                    != basis.realm_id
            {
                return Err("Ghost completion managed Actor payload is misbound".into());
            }
            (
                request,
                Some(&ghost.managed_actor_bundle),
                payload.actor_id,
                ScopeRef::Realm {
                    realm_id: basis.realm_id.clone(),
                },
            )
        }
    };

    request
        .validate_bindings()
        .map_err(|error| error.to_string())?;
    if let Some(bundle) = bundle {
        bundle
            .validate_bindings(request)
            .map_err(|error| error.to_string())?;
    }
    if request.basis.target_station_id() != authenticated_source_id {
        return Err(
            "authoring completion did not come from the targeted governance Station".into(),
        );
    }
    let Some(account_id) = actor_id.as_account_id() else {
        return Err("managed Actor completion does not carry a complete Account identity".into());
    };
    if &account_id.station_id != authenticated_source_id {
        return Err("managed Actor Account belongs to a different Station".into());
    }
    if request.basis.service_id() != expected_service_id {
        return Err("authoring completion targets a different Applet Service".into());
    }
    let basis_applet_id = match &request.basis {
        AppletManagedActorAuthoringBasis::InstallBot(basis) => &basis.applet_id,
        AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => &basis.applet_id,
    };
    if basis_applet_id != expected_applet_id {
        return Err("authoring completion basis names a different Applet".into());
    }
    let CommitStreamRef::Realm { realm_id } = &body.authoring_context.realm_stream_head.stream_ref
    else {
        return Err("authoring completion reports a non-Realm commit stream".into());
    };
    if Some(realm_id) != realm_from_scope(&effective_scope) {
        return Err("authoring completion Realm stream differs from its request scope".into());
    }

    let applet_evidence = &body
        .authoring_context
        .applet_service_signer_evidence
        .authenticated_signer_evidence;
    let managed_evidence = &body
        .authoring_context
        .managed_actor_signer_evidence
        .authenticated_signer_evidence;
    let attester_evidence = &body
        .authoring_context
        .managed_actor_signer_evidence
        .attester_signer_evidence;
    if &applet_evidence.subject_id != expected_service_id
        || &managed_evidence.subject_id != actor_id.signing_principal_id()
        || &attester_evidence.subject_id != authenticated_source_id
    {
        return Err("authoring completion signer evidence is bound to another identity".into());
    }
    Ok(ManagedAuthoringIdentity {
        applet_id: expected_applet_id.clone(),
        actor_id,
        effective_scope,
    })
}

impl AuthoringJournal {
    pub fn new(store: Arc<dyn AuthoringStore>) -> Self {
        Self { store }
    }

    /// Freeze the exact request/bundle authored by this runtime before it is
    /// handed to a Station. A completion is never installable unless this row
    /// already exists byte-for-byte; authenticated delivery alone is not an
    /// authority to substitute a different managed identity or bundle.
    pub(crate) fn prepare_managed_authoring(
        &self,
        committed_request: &AppletManagedActorCommittedRequest,
    ) -> Result<bool> {
        let request_digest = managed_authoring_request(committed_request).canonical_digest()?;
        let key = managed_authoring_preparation_key(&request_digest);
        let raw = String::from_utf8(arkret::canonical::canonical_json_bytes(committed_request)?)
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        if let Some(existing) = self.store.load(&key)? {
            return if existing == raw {
                Ok(false)
            } else {
                Err(BridgeError::App(
                    "authoring request digest is already prepared with different bytes".into(),
                ))
            };
        }
        if self
            .store
            .compare_exchange_batch(&[(key.clone(), None)], &[(key, Some(raw))])?
        {
            Ok(true)
        } else {
            Err(BridgeError::Runtime(
                "managed Actor authoring preparation contended; retry the same request".into(),
            ))
        }
    }

    /// Atomically install one fully validated managed-Actor completion. The
    /// immutable request row makes exact replay distinguishable from a reused
    /// request digest, while the current row advances only within the same
    /// Realm stream. A late valid completion is retained for historical proof
    /// verification without moving the current pointer backwards.
    pub(crate) fn install_managed_authoring(
        &self,
        identity: &ManagedAuthoringIdentity,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<ManagedAuthoringInstall> {
        let request = managed_authoring_request(&body.authoring_context.committed_request);
        let request_digest = request.canonical_digest()?;
        let prepared_key = managed_authoring_preparation_key(&request_digest);
        let prepared_request = self.store.load(&prepared_key)?.ok_or_else(|| {
            BridgeError::App(
                "managed Actor authoring completion has no locally prepared request".into(),
            )
        })?;
        let committed_request_raw = String::from_utf8(arkret::canonical::canonical_json_bytes(
            &body.authoring_context.committed_request,
        )?)
        .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        if prepared_request != committed_request_raw {
            return Err(BridgeError::App(
                "managed Actor authoring completion differs from the locally prepared request"
                    .into(),
            ));
        }
        let completion_key = managed_authoring_completion_key(identity, &request_digest)?;
        let current_key = managed_authoring_current_key(identity)?;
        let body_raw = String::from_utf8(arkret::canonical::canonical_json_bytes(body)?)
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;

        if let Some(existing) = self.store.load(&completion_key)? {
            return if existing == body_raw {
                Ok(ManagedAuthoringInstall::ExactReplay)
            } else {
                Err(BridgeError::App(
                    "authoring request digest is already bound to a different completion".into(),
                ))
            };
        }

        let current_raw = self.store.load(&current_key)?;
        let mut expected = vec![(completion_key.clone(), None)];
        let mut writes = vec![(completion_key, Some(body_raw.clone()))];
        if let Some(current_raw) = current_raw {
            let current: AppletAuthoringTransactionRequestBody =
                serde_json::from_str(&current_raw)?;
            let old_head = &current.authoring_context.realm_stream_head;
            let new_head = &body.authoring_context.realm_stream_head;
            if old_head.stream_ref != new_head.stream_ref {
                return Err(BridgeError::App(
                    "authoring completion cannot replace a different commit stream".into(),
                ));
            }
            if old_head.stream_position == new_head.stream_position {
                if old_head.commit_id != new_head.commit_id || current_raw != body_raw {
                    return Err(BridgeError::App(
                        "authoring completion conflicts at the current stream position".into(),
                    ));
                }
            } else if old_head.stream_position < new_head.stream_position {
                expected.push((current_key.clone(), Some(current_raw)));
                writes.push((current_key, Some(body_raw)));
            }
        } else {
            expected.push((current_key.clone(), None));
            writes.push((current_key, Some(body_raw)));
        }

        if self.store.compare_exchange_batch(&expected, &writes)? {
            Ok(ManagedAuthoringInstall::Installed)
        } else {
            Err(BridgeError::Runtime(
                "managed Actor authoring installation contended; retry the same completion".into(),
            ))
        }
    }

    /// Whether this exact completion was already durably installed. This is a
    /// replay-only migration seam for a crash after the completion CAS but
    /// before the HTTP idempotency outcome was recorded. It never authorizes a
    /// new body and never writes state.
    pub(crate) fn is_exact_managed_authoring_replay(
        &self,
        identity: &ManagedAuthoringIdentity,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<bool> {
        let request = managed_authoring_request(&body.authoring_context.committed_request);
        let request_digest = request.canonical_digest()?;
        let completion_key = managed_authoring_completion_key(identity, &request_digest)?;
        let Some(installed) = self.store.load(&completion_key)? else {
            return Ok(false);
        };
        let body_raw = String::from_utf8(arkret::canonical::canonical_json_bytes(body)?)
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        Ok(installed == body_raw)
    }

    pub(crate) fn load_managed_authoring(
        &self,
        identity: &ManagedAuthoringIdentity,
    ) -> Result<Option<AppletAuthoringTransactionRequestBody>> {
        self.store
            .load(&managed_authoring_current_key(identity)?)?
            .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
            .transpose()
    }

    pub(crate) async fn load_operation(
        &self,
        scope: &str,
        operation: &str,
    ) -> Result<Option<PublicationRecord>> {
        let store = self.store.clone();
        let scope = scope.to_owned();
        let operation = operation.to_owned();
        crate::run_blocking(move || load_operation(store.as_ref(), &scope, &operation)).await
    }

    pub(crate) async fn operation_for_event(
        &self,
        event: &arkret::EventId,
    ) -> Result<Option<(String, String)>> {
        let store = self.store.clone();
        let key = event_key(event);
        crate::run_blocking(move || {
            store
                .load(&key)?
                .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
                .transpose()
        })
        .await
    }

    /// Freeze a newly authored publication under `operation`. The signed bytes,
    /// the result row and the event index become durable in one atomic write,
    /// before the first transport attempt.
    pub(crate) async fn freeze(
        &self,
        scope: &str,
        operation: &str,
        record: &PublicationRecord,
    ) -> Result<bool> {
        record.validate(scope)?;
        let store = self.store.clone();
        let scope = scope.to_owned();
        let operation = operation.to_owned();
        let frozen = serde_json::to_string(record)?;
        let index = serde_json::to_string(&(&scope, &operation))?;
        let event_index = event_key(record.authored.event_id());
        crate::run_blocking(move || {
            let operation_row = operation_key(&scope, &operation)?;
            let result_row = result_key(&scope, &operation)?;
            let pending_row = pending_key(&scope, &operation)?;
            let expected = vec![
                (operation_row.clone(), None),
                (result_row.clone(), None),
                (event_index.clone(), None),
            ];
            let writes = vec![
                (operation_row, Some(frozen)),
                (
                    result_row,
                    Some(serde_json::to_string(&RecordedResult {
                        outcome: None,
                        committed: None,
                        observation_count: 0,
                    })?),
                ),
                (event_index, Some(index)),
                (pending_row, Some(operation.clone())),
            ];
            store.compare_exchange_batch(&expected, &writes)
        })
        .await
    }

    /// Persist one Station answer atomically with the pending index it settles.
    /// An accepted answer also retains the exact [`CommittedEventRef`].
    pub(crate) async fn record_outcome(
        &self,
        scope: &str,
        operation: &str,
        station: &DidCoreId,
        outcome: &AuthoritySubmitOutcome,
        committed: Option<&CommittedEventRef>,
    ) -> Result<bool> {
        let store = self.store.clone();
        let scope = scope.to_owned();
        let operation = operation.to_owned();
        let station = station.clone();
        let outcome = outcome.clone();
        let committed = committed.cloned();
        crate::run_blocking(move || {
            let Some(record) = load_operation(store.as_ref(), &scope, &operation)? else {
                return Err(BridgeError::Database(
                    "frozen publication disappeared".into(),
                ));
            };
            let result_row = result_key(&scope, &operation)?;
            let pending_row = pending_key(&scope, &operation)?;
            let count = record
                .observation_count
                .checked_add(1)
                .ok_or_else(|| BridgeError::Database("observation index exhausted".into()))?;
            let observation_row = format!(
                "observation/{}",
                serde_json::to_string(&(&scope, &operation, count))?
            );
            let expected = vec![
                (result_row.clone(), record.result_raw.clone()),
                (observation_row.clone(), None),
            ];
            let writes = vec![
                (
                    result_row,
                    Some(serde_json::to_string(&RecordedResult {
                        outcome: Some(outcome.clone()),
                        committed: committed.clone(),
                        observation_count: count,
                    })?),
                ),
                (
                    observation_row,
                    Some(serde_json::to_string(&StationObservation {
                        station,
                        outcome,
                    })?),
                ),
                // A settled publication leaves the restart replay set. Retryable
                // unavailability is settled by the caller re-opening it.
                (pending_row, None),
            ];
            store.compare_exchange_batch(&expected, &writes)
        })
        .await
    }

    /// Re-open a publication whose last answer was not an acceptance. The frozen
    /// bytes stay immutable; only the replay index is restored.
    pub(crate) async fn reopen(&self, scope: &str, operation: &str) -> Result<bool> {
        let store = self.store.clone();
        let scope = scope.to_owned();
        let operation = operation.to_owned();
        crate::run_blocking(move || {
            let Some(record) = load_operation(store.as_ref(), &scope, &operation)? else {
                return Err(BridgeError::Database(
                    "frozen publication disappeared".into(),
                ));
            };
            if record.committed.is_some() {
                return Err(BridgeError::Database(
                    "an accepted publication cannot be re-opened".into(),
                ));
            }
            let pending_row = pending_key(&scope, &operation)?;
            store.compare_exchange_batch(
                &[(pending_row.clone(), None)],
                &[(pending_row, Some(operation.clone()))],
            )
        })
        .await
    }

    /// Exact signed Events still awaiting a settled Station answer.
    pub async fn pending_events(&self) -> Result<Vec<AuthoredEvent>> {
        let store = self.store.clone();
        crate::run_blocking(move || {
            let mut result = Vec::new();
            for (key, operation) in store.entries_with_prefix("pending/")? {
                let raw = key
                    .strip_prefix("pending/")
                    .ok_or_else(|| BridgeError::Database("invalid pending index".into()))?;
                let (scope, indexed): (String, String) = serde_json::from_str(raw)?;
                if indexed != operation {
                    return Err(BridgeError::Database("pending index mismatch".into()));
                }
                // A concurrent completion can remove the pending index after this scan.
                if let Some(record) = load_operation(store.as_ref(), &scope, &operation)?
                    && record.committed.is_none()
                {
                    result.push(record.authored);
                }
            }
            Ok(result)
        })
        .await
    }
}

fn load_operation(
    store: &dyn AuthoringStore,
    scope: &str,
    operation: &str,
) -> Result<Option<PublicationRecord>> {
    let Some(raw) = store.load(&operation_key(scope, operation)?)? else {
        return Ok(None);
    };
    let mut record: PublicationRecord = serde_json::from_str(&raw)?;
    record.result_raw = store.load(&result_key(scope, operation)?)?;
    let raw = record
        .result_raw
        .as_ref()
        .ok_or_else(|| BridgeError::Database("publication has no atomic result row".into()))?;
    let result: RecordedResult = serde_json::from_str(raw)?;
    record.outcome = result.outcome;
    record.committed = result.committed;
    record.observation_count = result.observation_count;
    record.validate(scope)?;
    Ok(Some(record))
}

impl PublicationRecord {
    pub(crate) fn new(intent: EventIntent, authored: AuthoredEvent) -> Self {
        Self {
            intent,
            authored,
            outcome: None,
            committed: None,
            result_raw: None,
            observation_count: 0,
        }
    }

    fn validate(&self, scope: &str) -> Result<()> {
        let event = self.authored.event();
        self.authored.verify_identity()?;
        let realm = event
            .scope_ref
            .realm_id_opt()
            .ok_or_else(|| BridgeError::Database("publication has no Realm".into()))?;
        if scope_key(realm, &event.actor_id)? != scope
            || !self.intent.matches_authored_event(event)
            || event.producer_proof.is_none()
        {
            return Err(BridgeError::Database("invalid frozen publication".into()));
        }
        match &self.outcome {
            Some(outcome) => {
                let committed = publication_outcome(&self.authored, outcome)?;
                if committed.as_ref() != self.committed.as_ref() {
                    return Err(BridgeError::Database(
                        "retained committed reference disagrees with the recorded answer".into(),
                    ));
                }
            }
            None if self.committed.is_some() => {
                return Err(BridgeError::Database(
                    "committed reference without a recorded answer".into(),
                ));
            }
            None => {}
        }
        Ok(())
    }
}

/// Classify one Station answer for a frozen publication.
///
/// `Ok(Some(committed))` is an acceptance carrying the exact committed
/// reference. `Ok(None)` is a terminal Station rejection: the publication is
/// settled and must not be replayed automatically. `Err` means the answer
/// settles nothing, so the exact signed bytes stay replayable.
pub(crate) fn publication_outcome(
    event: &AuthoredEvent,
    outcome: &AuthoritySubmitOutcome,
) -> Result<Option<CommittedEventRef>> {
    match outcome {
        AuthoritySubmitOutcome::Accepted { status, commit } => {
            commit
                .validate_shape()
                .map_err(|error| BridgeError::Arkret(error.to_string()))?;
            if !matches!(
                status,
                AuthorityCommitStatus::Committed | AuthorityCommitStatus::Duplicate
            ) || &commit.event_ref != event.event_id()
            {
                return Err(BridgeError::Arkret(
                    "publication remains pending: the commit does not cover this Event".into(),
                ));
            }
            if commit.stream_ref.realm_id() != &event.realm_id {
                return Err(BridgeError::Arkret(
                    "publication remains pending: the commit belongs to another Realm".into(),
                ));
            }
            Ok(Some(CommittedEventRef {
                event_id: event.event_id().clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            }))
        }
        AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::Rejected,
            ..
        } => Ok(None),
        AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::RetryableUnavailable,
            reason_code,
        } => Err(BridgeError::Runtime(format!(
            "governance Station is unavailable: {reason_code}"
        ))),
    }
}

/// Stable bridge operation identity from the upstream delivery identity, not message content.
pub fn external_operation_key(
    kind: &str,
    external_ref: &BTreeMap<String, serde_json::Value>,
) -> Result<String> {
    if external_ref.is_empty() {
        return Err(BridgeError::App(
            "publication requires stable upstream delivery provenance".into(),
        ));
    }
    Ok(serde_json::to_string(&(kind, external_ref))?)
}

#[cfg(feature = "db")]
pub struct DbAuthoringStore {
    db: Arc<crate::db::DatabaseManager>,
}
#[cfg(feature = "db")]
mod schema {
    diesel::table! { authoring_journal (entry_key) { entry_key -> Text, entry_value -> Text, } }
}
#[cfg(feature = "db")]
impl DbAuthoringStore {
    pub fn new(db: Arc<crate::db::DatabaseManager>) -> Result<Self> {
        db.run_migrations(crate::db::MIGRATIONS)?;
        Ok(Self { db })
    }
}
#[cfg(feature = "db")]
impl AuthoringStore for DbAuthoringStore {
    fn load(&self, key: &str) -> Result<Option<String>> {
        use diesel::prelude::*;
        use schema::authoring_journal::dsl;
        let mut conn = self.db.conn()?;
        Ok(dsl::authoring_journal
            .filter(dsl::entry_key.eq(key))
            .select(dsl::entry_value)
            .first(&mut conn)
            .optional()?)
    }
    fn compare_exchange_batch(
        &self,
        expected: &[(String, Option<String>)],
        writes: &[(String, Option<String>)],
    ) -> Result<bool> {
        use diesel::prelude::*;
        use schema::authoring_journal::dsl;
        let mut conn = self.db.conn()?;
        let result = conn.transaction::<(), diesel::result::Error, _>(|conn| {
            // Conditional updates lock existing guards. Inserting absent guards
            // claims their unique keys; rollback removes every speculative guard.
            let mut checks: Vec<_> = expected.iter().collect();
            checks.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in checks {
                let count = match value {
                    Some(value) => diesel::update(
                        dsl::authoring_journal
                            .filter(dsl::entry_key.eq(key))
                            .filter(dsl::entry_value.eq(value)),
                    )
                    .set(dsl::entry_value.eq(value))
                    .execute(conn)?,
                    None => diesel::insert_into(dsl::authoring_journal)
                        .values((dsl::entry_key.eq(key), dsl::entry_value.eq("")))
                        .on_conflict(dsl::entry_key)
                        .do_nothing()
                        .execute(conn)?,
                };
                if count != 1 {
                    return Err(diesel::result::Error::RollbackTransaction);
                }
            }
            for (key, value) in expected {
                if value.is_none() && !writes.iter().any(|(written, _)| written == key) {
                    diesel::delete(dsl::authoring_journal.filter(dsl::entry_key.eq(key)))
                        .execute(conn)?;
                }
            }
            for (key, value) in writes {
                match value {
                    Some(value) => {
                        diesel::insert_into(dsl::authoring_journal)
                            .values((dsl::entry_key.eq(key), dsl::entry_value.eq(value)))
                            .on_conflict(dsl::entry_key)
                            .do_update()
                            .set(dsl::entry_value.eq(value))
                            .execute(conn)?;
                    }
                    None => {
                        diesel::delete(dsl::authoring_journal.filter(dsl::entry_key.eq(key)))
                            .execute(conn)?;
                    }
                }
            }
            Ok(())
        });
        match result {
            Ok(()) => Ok(true),
            Err(diesel::result::Error::RollbackTransaction) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn entries_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        use diesel::prelude::*;
        use schema::authoring_journal::dsl;
        let mut conn = self.db.conn()?;
        // Prefixes are private fixed ASCII namespaces, never caller SQL patterns.
        Ok(dsl::authoring_journal
            .filter(dsl::entry_key.ge(prefix))
            .filter(dsl::entry_key.lt(format!("{prefix}\u{10ffff}")))
            .select((dsl::entry_key, dsl::entry_value))
            .order(dsl::entry_key.asc())
            .load(&mut conn)?)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod database_tests {
    use super::*;
    #[test]
    fn atomic_indexed_cas_rolls_back_all_rows_and_preserves_guards() {
        let database = Arc::new(
            crate::db::DatabaseManager::connect(&crate::config::DatabaseConfig {
                url: ":memory:".into(),
                pool_size: 1,
            })
            .unwrap(),
        );
        let store = DbAuthoringStore::new(database).unwrap();
        assert!(
            store
                .compare_exchange_batch(
                    &[("head/a".into(), None), ("operation/a".into(), None)],
                    &[
                        ("head/a".into(), Some("pending".into())),
                        ("operation/a".into(), Some("exact signed bytes".into()))
                    ]
                )
                .unwrap()
        );
        assert!(
            !store
                .compare_exchange_batch(
                    &[
                        ("aaa-new-guard".into(), None),
                        ("head/a".into(), Some("stale".into()))
                    ],
                    &[("head/a".into(), Some("accepted".into()))]
                )
                .unwrap()
        );
        assert_eq!(store.load("aaa-new-guard").unwrap(), None);
        assert_eq!(store.load("head/a").unwrap().as_deref(), Some("pending"));
        assert_eq!(
            store.load("operation/a").unwrap().as_deref(),
            Some("exact signed bytes")
        );
        assert!(
            store
                .compare_exchange_batch(&[("guard-only".into(), None)], &[])
                .unwrap()
        );
        assert_eq!(store.load("guard-only").unwrap(), None);
        assert_eq!(store.entries_with_prefix("operation/").unwrap().len(), 1);
    }
}
