//! Indexed durable authoring for authority-commit publication.
//!
//! The journal keeps exactly one frozen, producer-signed Event per stable
//! upstream operation id, plus the exact [`CommittedEventRef`] the current
//! governance Station returned for it. It carries no predecessor, position,
//! or basis: Event order is fixed by the Station's `RealmCommit` in one
//! independent stream and is never reconstructed from producer-side state.
use std::collections::BTreeMap;
use std::sync::Arc;

use arkret::{ActorId, AuthoredEvent, EventIntent, RealmId};
use arkret_identifiers::DidCoreId;
use arkret_wire::{
    AuthorityCommitStatus, AuthorityRejectionStatus, AuthoritySubmitOutcome, CommittedEventRef,
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
    pub outcome: Option<StationAnswer>,
    /// Exact committed reference for an accepted publication.
    #[serde(skip)]
    pub committed: Option<CommittedEventRef>,
    #[serde(skip)]
    pub result_raw: Option<String>,
    #[serde(skip)]
    pub observation_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
pub(crate) enum StationAnswer {
    Authority(AuthoritySubmitOutcome),
    Applet(arkret::AppletTransactionOutcome),
}

/// One answer observed from one governance Station for this publication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StationObservation {
    pub station: DidCoreId,
    pub outcome: StationAnswer,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedResult {
    outcome: Option<StationAnswer>,
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

impl AuthoringJournal {
    pub fn new(store: Arc<dyn AuthoringStore>) -> Self {
        Self { store }
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
        self.record_answer(
            scope,
            operation,
            station,
            &StationAnswer::Authority(outcome.clone()),
            committed,
        )
        .await
    }

    pub(crate) async fn record_applet_outcome(
        &self,
        scope: &str,
        operation: &str,
        station: &DidCoreId,
        outcome: &arkret::AppletTransactionOutcome,
        committed: Option<&CommittedEventRef>,
    ) -> Result<bool> {
        self.record_answer(
            scope,
            operation,
            station,
            &StationAnswer::Applet(outcome.clone()),
            committed,
        )
        .await
    }

    async fn record_answer(
        &self,
        scope: &str,
        operation: &str,
        station: &DidCoreId,
        outcome: &StationAnswer,
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
                let committed = match outcome {
                    StationAnswer::Authority(outcome) => {
                        publication_outcome(&self.authored, outcome)?
                    }
                    StationAnswer::Applet(outcome) => {
                        applet_publication_outcome(&self.authored, outcome)?
                    }
                };
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

/// A transaction response is an authenticated operation result, not a fabricated
/// RealmCommit. Preserve its exact registered reference and its original carrier.
pub(crate) fn applet_publication_outcome(
    event: &AuthoredEvent,
    outcome: &arkret::AppletTransactionOutcome,
) -> Result<Option<CommittedEventRef>> {
    let refs = outcome.committed_event_refs();
    if outcome.status() == arkret::AppletTransactionStatus::Accepted
        && refs.len() == 1
        && outcome.rejections().is_empty()
        && refs[0].event_id == *event.event_id()
        && refs[0].stream_ref == arkret::CommitStreamRef::from_scope(&event.scope_ref, None)?
    {
        return Ok(Some(refs[0].clone()));
    }
    if outcome.retry_after_ms().is_some() {
        return Err(BridgeError::Runtime(
            "Applet transaction remains retryable".into(),
        ));
    }
    if outcome.status() == arkret::AppletTransactionStatus::Rejected
        && refs.is_empty()
        && outcome.rejections().len() == 1
        && outcome.rejections()[0].event_id.as_ref() == Some(event.event_id())
    {
        return Ok(None);
    }
    Err(BridgeError::Arkret(
        "Applet response does not settle the exact single Event".into(),
    ))
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
