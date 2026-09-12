//! Durable ordinary publication journal. Protocol envelopes and frontiers stay SDK-owned.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret::{ActorId, AuthoredEvent, EventIntent, RealmId};
use arkret_models_collaboration::event_sync::RealmActorFrontierView;
use arkret_models_collaboration::http_bodies::{EventsSubmitOutcome, EventsSubmitStatus};
use serde::{Deserialize, Serialize};

use crate::{BridgeError, Result};

/// Host persistence boundary. A successful CAS is durable before returning.
/// Implementations must serialize across instances and processes, not just clones.
pub trait AuthoringStore: Send + Sync + 'static {
    fn load(&self, scope: &str) -> Result<Option<String>>;
    fn compare_exchange(
        &self,
        scope: &str,
        expected: Option<&str>,
        replacement: &str,
    ) -> Result<bool>;
    fn entries(&self) -> Result<Vec<(String, String)>>;
}

#[derive(Clone)]
pub struct AuthoringJournal {
    pub(crate) store: Arc<dyn AuthoringStore>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeJournal {
    pub frontier: RealmActorFrontierView,
    pub pending: Option<String>,
    pub operations: BTreeMap<String, PublicationRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationRecord {
    pub basis: RealmActorFrontierView,
    pub intent: EventIntent,
    /// Exact signed SDK envelope including the original proof; never re-signed on retry.
    pub authored: AuthoredEvent,
    pub outcome: Option<EventsSubmitOutcome>,
    /// Receiver-local observations survive later explicit retries; they are not global finality.
    pub observations: Vec<ReceiverObservation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverObservation {
    pub receiver: arkret::Did,
    pub outcome: EventsSubmitOutcome,
}

pub(crate) fn scope_key(realm: &RealmId, actor: &ActorId) -> Result<String> {
    Ok(serde_json::to_string(&(realm, actor))?)
}

impl AuthoringJournal {
    pub fn new(store: Arc<dyn AuthoringStore>) -> Self {
        Self { store }
    }

    pub(crate) async fn load(&self, key: &str) -> Result<Option<(String, ScopeJournal)>> {
        let store = self.store.clone();
        let key = key.to_owned();
        crate::run_blocking(move || {
            store
                .load(&key)?
                .map(|raw| {
                    let state: ScopeJournal = serde_json::from_str(&raw)?;
                    state.validate(&key)?;
                    Ok((raw, state))
                })
                .transpose()
        })
        .await
    }

    pub(crate) async fn cas(
        &self,
        key: &str,
        expected: Option<&str>,
        state: &ScopeJournal,
    ) -> Result<bool> {
        state.validate(key)?;
        let store = self.store.clone();
        let key = key.to_owned();
        let expected = expected.map(str::to_owned);
        let replacement = serde_json::to_string(state)?;
        crate::run_blocking(move || store.compare_exchange(&key, expected.as_deref(), &replacement))
            .await
    }

    /// Load frozen pending publications for recovery without any authority/frontier lookup.
    pub async fn pending_events(&self) -> Result<Vec<AuthoredEvent>> {
        let store = self.store.clone();
        crate::run_blocking(move || {
            let mut events = Vec::new();
            for (key, raw) in store.entries()? {
                let state: ScopeJournal = serde_json::from_str(&raw)?;
                state.validate(&key)?;
                if let Some(operation) = &state.pending {
                    events.push(state.operations[operation].authored.clone());
                }
            }
            Ok(events)
        })
        .await
    }
}

impl ScopeJournal {
    pub fn new(frontier: RealmActorFrontierView) -> Self {
        Self {
            frontier,
            pending: None,
            operations: BTreeMap::new(),
        }
    }

    fn validate(&self, key: &str) -> Result<()> {
        self.frontier.validate()?;
        if scope_key(&self.frontier.realm_id, &self.frontier.actor_id)? != key {
            return Err(BridgeError::Database(
                "authoring journal scope mismatch".into(),
            ));
        }
        for (operation, record) in &self.operations {
            let event = record.authored.event();
            record.authored.verify_identity()?;
            if event.realm_id_opt() != Some(&self.frontier.realm_id)
                || event.actor_id != self.frontier.actor_id
                || !record.intent.authored_envelope_matches(event)
                || event.proofs.len() != 1
            {
                return Err(BridgeError::Database(
                    "invalid frozen ordinary publication".into(),
                ));
            }
            record
                .basis
                .validate_with_suite(record.authored.digest_suite())?;
            if record.basis.realm_id != self.frontier.realm_id
                || record.basis.actor_id != self.frontier.actor_id
                || record.authored.actor_seq != record.basis.next_actor_seq
                || record
                    .basis
                    .frontier_event_ids
                    .iter()
                    .any(|id| !record.authored.prev_refs.contains(id))
            {
                return Err(BridgeError::Database(
                    "frozen publication differs from its authoring basis".into(),
                ));
            }
            if let Some(outcome) = &record.outcome {
                publication_outcome(&record.authored, outcome)?;
            }
            if record.outcome.is_none() != (self.pending.as_ref() == Some(operation)) {
                return Err(BridgeError::Database(
                    "authoring pending index mismatch".into(),
                ));
            }
        }
        if let Some(operation) = &self.pending {
            if !self.operations.contains_key(operation) {
                return Err(BridgeError::Database("missing pending publication".into()));
            }
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
            if Some(&frontier.realm_id) != event.realm_id_opt()
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
    diesel::table! { ordinary_authoring (scope_key) { scope_key -> Text, journal -> Text, } }
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
        Ok(dsl::ordinary_authoring
            .filter(dsl::scope_key.eq(key))
            .select(dsl::journal)
            .first(&mut self.db.conn()?)
            .optional()?)
    }
    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<&str>,
        replacement: &str,
    ) -> Result<bool> {
        use diesel::prelude::*;
        use schema::ordinary_authoring::dsl;
        let mut conn = self.db.conn()?;
        let written = match expected {
            Some(expected) => diesel::update(
                dsl::ordinary_authoring
                    .filter(dsl::scope_key.eq(key))
                    .filter(dsl::journal.eq(expected)),
            )
            .set(dsl::journal.eq(replacement))
            .execute(&mut conn)?,
            None => diesel::insert_into(dsl::ordinary_authoring)
                .values((dsl::scope_key.eq(key), dsl::journal.eq(replacement)))
                .on_conflict(dsl::scope_key)
                .do_nothing()
                .execute(&mut conn)?,
        };
        Ok(written == 1)
    }
    fn entries(&self) -> Result<Vec<(String, String)>> {
        use diesel::prelude::*;
        use schema::ordinary_authoring::dsl;
        Ok(dsl::ordinary_authoring
            .select((dsl::scope_key, dsl::journal))
            .load(&mut self.db.conn()?)?)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod database_tests {
    use super::*;
    #[test]
    fn database_cas_keeps_freeze_and_frontier_in_one_durable_row() {
        let db = Arc::new(
            crate::db::DatabaseManager::connect(&crate::DatabaseConfig {
                url: "sqlite://:memory:".into(),
                pool_size: 1,
            })
            .unwrap(),
        );
        let first = DbAuthoringStore::new(db.clone()).unwrap();
        let second = DbAuthoringStore::new(db).unwrap();
        assert!(
            first
                .compare_exchange("realm/actor", None, "frozen signed publication")
                .unwrap()
        );
        assert!(
            !second
                .compare_exchange("realm/actor", None, "competing publication")
                .unwrap()
        );
        assert!(
            !second
                .compare_exchange("realm/actor", Some("stale"), "wrong frontier")
                .unwrap()
        );
        assert!(
            second
                .compare_exchange(
                    "realm/actor",
                    Some("frozen signed publication"),
                    "accepted frontier and outcome"
                )
                .unwrap()
        );
        assert_eq!(
            first.load("realm/actor").unwrap().as_deref(),
            Some("accepted frontier and outcome")
        );
        assert!(
            first
                .compare_exchange("other-realm/actor", None, "independent scope")
                .unwrap()
        );
        assert_eq!(first.entries().unwrap().len(), 2);
    }
}
