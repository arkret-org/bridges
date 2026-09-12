//! Indexed durable ordinary authoring. Protocol envelopes and frontiers stay SDK-owned.
use std::collections::BTreeMap;
use std::sync::Arc;

use arkret::{ActorId, AuthoredEvent, EventIntent, RealmId};
use arkret_models_collaboration::event_sync::RealmActorFrontierView;
use arkret_models_collaboration::http_bodies::{EventsSubmitOutcome, EventsSubmitStatus};
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

/// Only the current height's bounded candidate summaries live in the hot head.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Candidate {
    pub event_id: arkret::EventId,
    pub prev_refs: Vec<arkret::EventId>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeJournal {
    pub frontier: RealmActorFrontierView,
    pub pending: Option<String>,
    pub candidate_seq: u64,
    pub candidates: Vec<Candidate>,
    /// Only records touched by this transaction; never serialized into the head.
    #[serde(skip)]
    pub operations: BTreeMap<String, PublicationRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationRecord {
    pub basis: RealmActorFrontierView,
    pub intent: EventIntent,
    pub authored: AuthoredEvent,
    #[serde(skip)]
    pub outcome: Option<EventsSubmitOutcome>,
    #[serde(skip)]
    pub observations: Vec<ReceiverObservation>,
    #[serde(skip)]
    pub result_raw: Option<String>,
    #[serde(skip)]
    pub observation_count: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverObservation {
    pub receiver: arkret::Did,
    pub outcome: EventsSubmitOutcome,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedResult {
    outcome: Option<EventsSubmitOutcome>,
    observation_count: u64,
}

pub(crate) fn scope_key(realm: &RealmId, actor: &ActorId) -> Result<String> {
    Ok(serde_json::to_string(&(realm, actor))?)
}
fn head_key(scope: &str) -> String {
    format!("head/{scope}")
}
fn pending_key(scope: &str) -> String {
    format!("pending/{scope}")
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
fn event_key(event: &arkret::EventId) -> String {
    format!("event/{event}")
}

impl AuthoringJournal {
    pub fn new(store: Arc<dyn AuthoringStore>) -> Self {
        Self { store }
    }
    pub(crate) async fn load(&self, scope: &str) -> Result<Option<(String, ScopeJournal)>> {
        let store = self.store.clone();
        let scope = scope.to_owned();
        crate::run_blocking(move || {
            store
                .load(&head_key(&scope))?
                .map(|raw| {
                    let state: ScopeJournal = serde_json::from_str(&raw)?;
                    state.validate(&scope)?;
                    Ok((raw, state))
                })
                .transpose()
        })
        .await
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
    pub(crate) async fn cas(
        &self,
        scope: &str,
        expected_head: Option<&str>,
        state: &ScopeJournal,
    ) -> Result<bool> {
        let mut state = state.clone();
        if state.candidate_seq != state.frontier.next_actor_seq {
            state.candidate_seq = state.frontier.next_actor_seq;
            state.candidates.clear();
        }
        for record in state.operations.values() {
            if record.authored.actor_seq == state.candidate_seq
                && !state
                    .candidates
                    .iter()
                    .any(|candidate| &candidate.event_id == record.authored.event_id())
            {
                state.candidates.push(Candidate {
                    event_id: record.authored.event_id().clone(),
                    prev_refs: record.authored.prev_refs.clone(),
                });
            }
        }
        state.validate(scope)?;
        let store = self.store.clone();
        let scope = scope.to_owned();
        let expected_head = expected_head.map(str::to_owned);
        crate::run_blocking(move || {
            let mut expected = vec![(head_key(&scope), expected_head)];
            let mut writes = vec![
                (head_key(&scope), Some(serde_json::to_string(&state)?)),
                (pending_key(&scope), state.pending.clone()),
            ];
            for (operation, record) in &state.operations {
                let key = operation_key(&scope, operation)?;
                let frozen = serde_json::to_string(record)?;
                match store.load(&key)? {
                    Some(existing) if existing != frozen => {
                        return Err(BridgeError::Database(
                            "immutable publication replacement rejected".into(),
                        ));
                    }
                    Some(_) => {}
                    None => {
                        expected.push((key.clone(), None));
                        writes.push((key, Some(frozen)));
                        let event_index = event_key(record.authored.event_id());
                        expected.push((event_index.clone(), None));
                        writes.push((
                            event_index,
                            Some(serde_json::to_string(&(&scope, operation))?),
                        ));
                    }
                }
                let result = result_key(&scope, operation)?;
                expected.push((result.clone(), record.result_raw.clone()));
                let mut count = record.observation_count;
                for observation in &record.observations {
                    count = count.checked_add(1).ok_or_else(|| {
                        BridgeError::Database("observation index exhausted".into())
                    })?;
                    let key = format!(
                        "observation/{}",
                        serde_json::to_string(&(&scope, operation, count))?
                    );
                    expected.push((key.clone(), None));
                    writes.push((key, Some(serde_json::to_string(observation)?)));
                }
                writes.push((
                    result,
                    Some(serde_json::to_string(&RecordedResult {
                        outcome: record.outcome.clone(),
                        observation_count: count,
                    })?),
                ));
            }
            store.compare_exchange_batch(&expected, &writes)
        })
        .await
    }
    pub async fn pending_events(&self) -> Result<Vec<AuthoredEvent>> {
        let store = self.store.clone();
        crate::run_blocking(move || {
            let mut result = Vec::new();
            for (key, operation) in store.entries_with_prefix("pending/")? {
                let scope = key
                    .strip_prefix("pending/")
                    .ok_or_else(|| BridgeError::Database("invalid pending index".into()))?;
                // A concurrent completion can remove the pending index after this scan.
                if let Some(record) = load_operation(store.as_ref(), scope, &operation)? {
                    if record.outcome.is_none() {
                        result.push(record.authored);
                    }
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
    record.observation_count = result.observation_count;
    record.validate(scope)?;
    Ok(Some(record))
}
impl ScopeJournal {
    pub fn new(frontier: RealmActorFrontierView) -> Self {
        Self {
            candidate_seq: frontier.next_actor_seq,
            frontier,
            pending: None,
            candidates: vec![],
            operations: BTreeMap::new(),
        }
    }
    fn validate(&self, key: &str) -> Result<()> {
        self.frontier.validate()?;
        if scope_key(&self.frontier.realm_id, &self.frontier.actor_id)? != key
            || self.candidate_seq != self.frontier.next_actor_seq
        {
            return Err(BridgeError::Database(
                "invalid authoring head scope or position".into(),
            ));
        }
        if self.candidates.len() > arkret_wire::event_envelope::MAX_ACTOR_SEQ_TOTAL_SIBLINGS {
            return Err(BridgeError::Database(
                "Actor height exceeds sibling bound".into(),
            ));
        }
        for candidate in &self.candidates {
            if self
                .candidates
                .iter()
                .filter(|other| other.prev_refs == candidate.prev_refs)
                .count()
                > arkret_wire::event_envelope::MAX_ACTOR_SEQ_SIBLINGS
            {
                return Err(BridgeError::Database(
                    "Actor predecessor bucket exceeds sibling bound".into(),
                ));
            }
        }
        for (operation, record) in &self.operations {
            record.validate(key)?;
            if record.outcome.is_none() != (self.pending.as_ref() == Some(operation)) {
                return Err(BridgeError::Database(
                    "pending publication index mismatch".into(),
                ));
            }
        }
        Ok(())
    }
}
impl PublicationRecord {
    fn validate(&self, scope: &str) -> Result<()> {
        let event = self.authored.event();
        self.authored.verify_identity()?;
        let realm = event
            .scope_ref
            .realm_id_opt()
            .ok_or_else(|| BridgeError::Database("publication has no Realm".into()))?;
        if scope_key(realm, &event.actor_id)? != scope
            || !self.intent.authored_envelope_matches(event)
            || event.proofs.len() != 1
        {
            return Err(BridgeError::Database("invalid frozen publication".into()));
        }
        self.basis
            .validate_with_suite(self.authored.digest_suite())?;
        if &self.basis.realm_id != realm
            || self.basis.actor_id != event.actor_id
            || event.actor_seq != self.basis.next_actor_seq
            || self
                .basis
                .frontier_event_ids
                .iter()
                .any(|id| !event.prev_refs.contains(id))
        {
            return Err(BridgeError::Database(
                "frozen publication differs from authoring basis".into(),
            ));
        }
        if let Some(outcome) = &self.outcome {
            publication_outcome(&self.authored, outcome)?;
        }
        Ok(())
    }
}

/// Only an exact, coherent business acceptance can terminate a pending publication.
/// Missing or incoherent results retain the pending attempt; no path burns an Actor slot.
pub(crate) fn accepted_frontier(
    event: &AuthoredEvent,
    outcome: &EventsSubmitOutcome,
) -> Result<RealmActorFrontierView> {
    outcome.validate_delivery_invariants()?;
    let id = event.event_id();
    if !matches!(
        outcome.status,
        EventsSubmitStatus::Accepted | EventsSubmitStatus::Duplicate
    ) || outcome.accepted.len() + outcome.duplicate.len() != 1
        || !outcome
            .accepted
            .iter()
            .chain(&outcome.duplicate)
            .any(|value| value == id)
        || !outcome.rejections.is_empty()
        || !outcome.quarantine.is_empty()
        || !outcome.control_proposal_acks.is_empty()
        || outcome.original_outcome.is_some()
    {
        return Err(BridgeError::Arkret(
            "publication remains pending: no exact ordinary acceptance".into(),
        ));
    }
    let realm = event
        .scope_ref
        .realm_id_opt()
        .ok_or_else(|| BridgeError::Arkret("ordinary publication lacks Realm".into()))?;
    if outcome.frontiers.len() != 1 {
        return Err(BridgeError::Arkret(
            "publication remains pending: missing exact actor frontier".into(),
        ));
    }
    let frontier = &outcome.frontiers[0];
    frontier.validate_with_suite(event.digest_suite())?;
    let next = event
        .actor_seq
        .checked_add(1)
        .ok_or_else(|| BridgeError::Arkret("actor sequence exhausted".into()))?;
    if &frontier.realm_id != realm
        || frontier.actor_id != event.actor_id
        || frontier.next_actor_seq < next
        || (frontier.next_actor_seq == next && !frontier.frontier_event_ids.contains(id))
    {
        return Err(BridgeError::Arkret(
            "publication remains pending: acceptance frontier does not cover Event".into(),
        ));
    }
    Ok(frontier.clone())
}

/// `None` is a receiver-local rejection, not a claim that the Event cannot
/// have been accepted elsewhere. A new operation can use the unchanged frontier.
pub(crate) fn publication_outcome(
    event: &AuthoredEvent,
    outcome: &EventsSubmitOutcome,
) -> Result<Option<RealmActorFrontierView>> {
    if outcome.status == EventsSubmitStatus::Partial
        && outcome.pending_delivery_count == 0
        && outcome.ingress_receipts.is_empty()
        && outcome.frontiers.len() <= 1
        && outcome.accepted.is_empty()
        && outcome.duplicate.is_empty()
        && outcome.quarantine.is_empty()
        && outcome.control_proposal_acks.is_empty()
        && outcome.original_outcome.is_none()
        && outcome.rejections.len() == 1
        && outcome.rejections[0].id == event.event_id().as_str()
        && outcome.rejections[0].index.is_none_or(|index| index == 0)
    {
        for frontier in &outcome.frontiers {
            frontier.validate_with_suite(event.digest_suite())?;
            if Some(&frontier.realm_id) != event.scope_ref.realm_id_opt()
                || frontier.actor_id != event.actor_id
            {
                return Err(BridgeError::Arkret(
                    "receiver rejection carries an unrelated frontier".into(),
                ));
            }
        }
        return Ok(None);
    }
    accepted_frontier(event, outcome).map(Some)
}

pub(crate) fn merge_frontier(
    current: &RealmActorFrontierView,
    observed: &RealmActorFrontierView,
    suite: arkret::DigestSuite,
) -> Result<RealmActorFrontierView> {
    observed.validate_with_suite(suite)?;
    if current.realm_id != observed.realm_id || current.actor_id != observed.actor_id {
        return Err(BridgeError::Arkret(
            "cannot merge different Actor frontier scopes".into(),
        ));
    }
    if observed.next_actor_seq < current.next_actor_seq {
        return Ok(current.clone());
    }
    if observed.next_actor_seq > current.next_actor_seq {
        return Ok(observed.clone());
    }
    let mut siblings = current.frontier_event_ids.clone();
    siblings.extend(observed.frontier_event_ids.iter().cloned());
    siblings.sort();
    siblings.dedup();
    Ok(RealmActorFrontierView::new(
        current.realm_id.clone(),
        current.actor_id.clone(),
        current.next_actor_seq,
        siblings,
        suite,
    )?)
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
    diesel::table! { ordinary_authoring (entry_key) { entry_key -> Text, entry_value -> Text, } }
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
        use schema::ordinary_authoring::dsl;
        let mut conn = self.db.conn()?;
        Ok(dsl::ordinary_authoring
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
        use schema::ordinary_authoring::dsl;
        let mut conn = self.db.conn()?;
        let result = conn.transaction::<(), diesel::result::Error, _>(|conn| {
            // Conditional updates lock existing guards. Inserting absent guards
            // claims their unique keys; rollback removes every speculative guard.
            let mut checks: Vec<_> = expected.iter().collect();
            checks.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in checks {
                let count = match value {
                    Some(value) => diesel::update(
                        dsl::ordinary_authoring
                            .filter(dsl::entry_key.eq(key))
                            .filter(dsl::entry_value.eq(value)),
                    )
                    .set(dsl::entry_value.eq(value))
                    .execute(conn)?,
                    None => diesel::insert_into(dsl::ordinary_authoring)
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
                    diesel::delete(dsl::ordinary_authoring.filter(dsl::entry_key.eq(key)))
                        .execute(conn)?;
                }
            }
            for (key, value) in writes {
                match value {
                    Some(value) => {
                        diesel::insert_into(dsl::ordinary_authoring)
                            .values((dsl::entry_key.eq(key), dsl::entry_value.eq(value)))
                            .on_conflict(dsl::entry_key)
                            .do_update()
                            .set(dsl::entry_value.eq(value))
                            .execute(conn)?;
                    }
                    None => {
                        diesel::delete(dsl::ordinary_authoring.filter(dsl::entry_key.eq(key)))
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
        use schema::ordinary_authoring::dsl;
        let mut conn = self.db.conn()?;
        // Prefixes are private fixed ASCII namespaces, never caller SQL patterns.
        Ok(dsl::ordinary_authoring
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
