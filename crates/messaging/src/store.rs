//! Channel/message/user mapping store and the DB-backed [`AppletResolver`].
//!
//! Owns the messaging mapping tables (`channel_realm_mappings`,
//! `message_mappings`, `user_mappings`) per applet-integration §10.1 / §16,
//! and answers the arkret server's actor/realm probes from them.

use std::sync::Arc;

use arkret_bridge_runtime::app::{AppletResolver, ResolvedActor, ResolvedRealm};
use arkret_bridge_runtime::db::DatabaseManager;
use arkret_bridge_runtime::{BridgeError, Result, run_blocking};
use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, embed_migrations};

pub use crate::models::{ChannelRealmMapping, MessageMapping, UserMapping};
use crate::models::{NewChannelRealmMapping, NewMessageMapping, NewUserMapping};
use crate::schema;

/// Embedded migrations for the messaging-owned mapping tables
/// (`channel_realm_mappings`, `message_mappings`, `user_mappings`). The backend
/// dialect is selected at compile time, matching the runtime's active
/// connection feature.
#[cfg(feature = "sqlite")]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgres");
#[cfg(all(feature = "mysql", not(feature = "sqlite"), not(feature = "postgres")))]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

pub(crate) fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Channel/message/user mapping store persisted through the runtime database.
pub struct MessageStore {
    db: Arc<DatabaseManager>,
}

impl MessageStore {
    pub fn new(db: Arc<DatabaseManager>) -> Result<Self> {
        db.run_migrations(MIGRATIONS)?;
        Ok(Self { db })
    }

    pub fn prepared_ghost_provision(&self, provision_key: &str) -> Result<Option<String>> {
        use schema::prepared_ghost_provisions::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::prepared_ghost_provisions
            .filter(dsl::provision_key.eq(provision_key))
            .select(dsl::request_json)
            .first::<String>(&mut conn)
            .optional()?)
    }

    pub async fn prepared_ghost_provision_async(
        self: Arc<Self>,
        provision_key: String,
    ) -> Result<Option<String>> {
        run_blocking(move || self.prepared_ghost_provision(&provision_key)).await
    }

    /// Persist the exact signed Ghost provisioning request before transport.
    /// A concurrent writer for the same tuple wins; all callers return the
    /// same durable bytes.
    pub fn prepare_ghost_provision(
        &self,
        provision_key: &str,
        request_json: &str,
    ) -> Result<String> {
        use schema::prepared_ghost_provisions::dsl;

        let mut conn = self.db.conn()?;
        let inserted = diesel::insert_into(dsl::prepared_ghost_provisions)
            .values((
                dsl::provision_key.eq(provision_key),
                dsl::request_json.eq(request_json),
                dsl::created_at.eq(now_ts()),
            ))
            .execute(&mut conn);
        match inserted {
            Ok(_) => Ok(request_json.to_owned()),
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => dsl::prepared_ghost_provisions
                .filter(dsl::provision_key.eq(provision_key))
                .select(dsl::request_json)
                .first::<String>(&mut conn)
                .map_err(Into::into),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn prepare_ghost_provision_async(
        self: Arc<Self>,
        provision_key: String,
        request_json: String,
    ) -> Result<String> {
        run_blocking(move || self.prepare_ghost_provision(&provision_key, &request_json)).await
    }

    pub fn upsert_channel_realm(
        &self,
        app_channel: &str,
        realm_id: &str,
        alias: Option<&str>,
    ) -> Result<()> {
        use schema::channel_realm_mappings::dsl;

        let mut conn = self.db.conn()?;
        let exists = dsl::channel_realm_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .first::<ChannelRealmMapping>(&mut conn)
            .optional()?;
        if let Some(existing) = exists {
            // A realm change invalidates the cached portal strand (the strand
            // belongs to the previous realm); it is re-resolved lazily.
            let portal_strand_id = if existing.arkret_realm_id == realm_id {
                existing.portal_strand_id.clone()
            } else {
                None
            };
            diesel::update(dsl::channel_realm_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::arkret_realm_id.eq(realm_id),
                    dsl::portal_alias.eq(alias),
                    dsl::portal_strand_id.eq(portal_strand_id),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::channel_realm_mappings)
                .values(NewChannelRealmMapping {
                    app_channel_id: app_channel,
                    arkret_realm_id: realm_id,
                    portal_alias: alias,
                    portal_strand_id: None,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    /// The full portal mapping row for an app channel (realm + cached portal
    /// strand, applet-integration §10.1).
    pub fn portal_for_channel(&self, app_channel: &str) -> Result<Option<ChannelRealmMapping>> {
        use schema::channel_realm_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::channel_realm_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .first::<ChannelRealmMapping>(&mut conn)
            .optional()?)
    }

    /// Persist the resolved portal strand for an app channel (§10.1 step 1 cache).
    pub fn set_channel_portal_strand(&self, app_channel: &str, strand_id: &str) -> Result<()> {
        use schema::channel_realm_mappings::dsl;

        let mut conn = self.db.conn()?;
        diesel::update(dsl::channel_realm_mappings.filter(dsl::app_channel_id.eq(app_channel)))
            .set(dsl::portal_strand_id.eq(Some(strand_id)))
            .execute(&mut conn)?;
        Ok(())
    }

    /// The portal mapping row for a realm (arkret → app direction).
    pub fn channel_for_realm(&self, realm_id: &str) -> Result<Option<ChannelRealmMapping>> {
        use schema::channel_realm_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::channel_realm_mappings
            .filter(dsl::arkret_realm_id.eq(realm_id))
            .first::<ChannelRealmMapping>(&mut conn)
            .optional()?)
    }

    pub fn record_message(
        &self,
        app_channel: &str,
        app_message_id: &str,
        normalized_sender: &str,
        arkret_event_id: &str,
        realm_id: &str,
    ) -> Result<()> {
        use schema::message_mappings::dsl;

        if app_channel.trim().is_empty() {
            return Err(BridgeError::App("app_channel must not be empty".into()));
        }
        if app_message_id.trim().is_empty() {
            return Err(BridgeError::App("app_message_id must not be empty".into()));
        }
        if normalized_sender.trim().is_empty() {
            return Err(BridgeError::App(
                "normalized_sender must not be empty".into(),
            ));
        }

        let mut conn = self.db.conn()?;
        let exists = dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
            .filter(dsl::normalized_sender.eq(normalized_sender))
            .first::<MessageMapping>(&mut conn)
            .optional()?;
        if let Some(existing) = exists {
            diesel::update(dsl::message_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::arkret_event_id.eq(arkret_event_id),
                    dsl::arkret_realm_id.eq(realm_id),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::message_mappings)
                .values(NewMessageMapping {
                    app_channel_id: app_channel,
                    app_message_id,
                    normalized_sender,
                    arkret_event_id,
                    arkret_realm_id: realm_id,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    /// Dedup lookup keyed by the §16 minimum key set: protocol/tenant/channel
    /// (folded into `app_channel`), external event id, and normalized sender.
    pub fn event_for_channel_message(
        &self,
        app_channel: &str,
        app_message_id: &str,
        normalized_sender: &str,
    ) -> Result<Option<String>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
            .filter(dsl::normalized_sender.eq(normalized_sender))
            .select(dsl::arkret_event_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    /// Resolve the target event for an app-side delete/recall. Delete webhooks
    /// often identify the deleted message and deleter, not the original sender,
    /// so this lookup intentionally does not participate in create-message
    /// deduplication.
    pub fn event_for_channel_message_target(
        &self,
        app_channel: &str,
        app_message_id: &str,
    ) -> Result<Option<String>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
            .order(dsl::created_at.asc())
            .select(dsl::arkret_event_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    pub fn app_message_for_event(&self, arkret_event_id: &str) -> Result<Option<MessageMapping>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::arkret_event_id.eq(arkret_event_id))
            .first::<MessageMapping>(&mut conn)
            .optional()?)
    }

    // The argument list mirrors the user_mappings row shape one-to-one; a
    // params struct would only restate the same fields.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_user(
        &self,
        protocol: &str,
        tenant: &str,
        external_user_id: &str,
        actor_id: &str,
        profile_event_ref: &str,
        accountability_grant_ref: &str,
        authorization_ref: &str,
        display: Option<&str>,
    ) -> Result<()> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        // Ghost provisioning races: the same external user can first appear on two
        // channels concurrently (BRG-02-004). The serial domain key is the channel,
        // but the user mapping's unique key is (protocol, tenant, external_user_id),
        // so both racers can reach `insert` and one would hit a UNIQUE violation.
        // Try insert first; on a conflict, fall back to update by the conflict key
        // (an atomic upsert in effect, portable across sqlite/postgres/mysql and
        // matching the existing dedup-store pattern). The losing racer then re-reads
        // the winner's mapping (via `ghost_actor_for_app_user`) and continues
        // submitting rather than failing the message.
        let inserted = diesel::insert_into(dsl::user_mappings)
            .values(NewUserMapping {
                protocol,
                tenant,
                external_user_id,
                arkret_actor_id: actor_id,
                profile_event_ref,
                accountability_grant_ref,
                authorization_ref,
                display_name: display,
                created_at: now_ts(),
            })
            .execute(&mut conn);
        match inserted {
            Ok(_) => Ok(()),
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                diesel::update(
                    dsl::user_mappings
                        .filter(dsl::protocol.eq(protocol))
                        .filter(dsl::tenant.eq(tenant))
                        .filter(dsl::external_user_id.eq(external_user_id)),
                )
                .set((
                    dsl::arkret_actor_id.eq(actor_id),
                    dsl::profile_event_ref.eq(profile_event_ref),
                    dsl::accountability_grant_ref.eq(accountability_grant_ref),
                    dsl::authorization_ref.eq(authorization_ref),
                    dsl::display_name.eq(display),
                ))
                .execute(&mut conn)?;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn ghost_actor_for_app_user(
        &self,
        protocol: &str,
        tenant: &str,
        external_user_id: &str,
    ) -> Result<Option<UserMapping>> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::user_mappings
            .filter(dsl::protocol.eq(protocol))
            .filter(dsl::tenant.eq(tenant))
            .filter(dsl::external_user_id.eq(external_user_id))
            .first::<UserMapping>(&mut conn)
            .optional()?)
    }

    /// Reverse lookup for ghost resolution: find the user row by arkret actor DID.
    pub fn user_by_actor(&self, actor_id: &str) -> Result<Option<UserMapping>> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::user_mappings
            .filter(dsl::arkret_actor_id.eq(actor_id))
            .first::<UserMapping>(&mut conn)
            .optional()?)
    }

    /// Reverse lookup for portal resolution: find the channel mapping by arkret
    /// realm id or by portal alias.
    pub fn channel_by_realm_or_alias(&self, key: &str) -> Result<Option<ChannelRealmMapping>> {
        use schema::channel_realm_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::channel_realm_mappings
            .filter(dsl::arkret_realm_id.eq(key).or(dsl::portal_alias.eq(key)))
            .first::<ChannelRealmMapping>(&mut conn)
            .optional()?)
    }
}

impl MessageStore {
    pub async fn portal_for_channel_async(
        self: Arc<Self>,
        app_channel: String,
    ) -> Result<Option<ChannelRealmMapping>> {
        run_blocking(move || self.portal_for_channel(&app_channel)).await
    }

    pub async fn set_channel_portal_strand_async(
        self: Arc<Self>,
        app_channel: String,
        strand_id: String,
    ) -> Result<()> {
        run_blocking(move || self.set_channel_portal_strand(&app_channel, &strand_id)).await
    }

    pub async fn channel_for_realm_async(
        self: Arc<Self>,
        realm_id: String,
    ) -> Result<Option<ChannelRealmMapping>> {
        run_blocking(move || self.channel_for_realm(&realm_id)).await
    }

    pub async fn record_message_async(
        self: Arc<Self>,
        app_channel: String,
        app_message_id: String,
        normalized_sender: String,
        arkret_event_id: String,
        realm_id: String,
    ) -> Result<()> {
        run_blocking(move || {
            self.record_message(
                &app_channel,
                &app_message_id,
                &normalized_sender,
                &arkret_event_id,
                &realm_id,
            )
        })
        .await
    }

    pub async fn event_for_channel_message_async(
        self: Arc<Self>,
        app_channel: String,
        app_message_id: String,
        normalized_sender: String,
    ) -> Result<Option<String>> {
        run_blocking(move || {
            self.event_for_channel_message(&app_channel, &app_message_id, &normalized_sender)
        })
        .await
    }

    pub async fn event_for_channel_message_target_async(
        self: Arc<Self>,
        app_channel: String,
        app_message_id: String,
    ) -> Result<Option<String>> {
        run_blocking(move || self.event_for_channel_message_target(&app_channel, &app_message_id))
            .await
    }

    pub async fn app_message_for_event_async(
        self: Arc<Self>,
        arkret_event_id: String,
    ) -> Result<Option<MessageMapping>> {
        run_blocking(move || self.app_message_for_event(&arkret_event_id)).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_user_async(
        self: Arc<Self>,
        protocol: String,
        tenant: String,
        external_user_id: String,
        actor_id: String,
        profile_event_ref: String,
        accountability_grant_ref: String,
        authorization_ref: String,
        display: Option<String>,
    ) -> Result<()> {
        run_blocking(move || {
            self.upsert_user(
                &protocol,
                &tenant,
                &external_user_id,
                &actor_id,
                &profile_event_ref,
                &accountability_grant_ref,
                &authorization_ref,
                display.as_deref(),
            )
        })
        .await
    }

    pub async fn ghost_actor_for_app_user_async(
        self: Arc<Self>,
        protocol: String,
        tenant: String,
        external_user_id: String,
    ) -> Result<Option<UserMapping>> {
        run_blocking(move || self.ghost_actor_for_app_user(&protocol, &tenant, &external_user_id))
            .await
    }

    pub async fn user_by_actor_async(
        self: Arc<Self>,
        actor_id: String,
    ) -> Result<Option<UserMapping>> {
        run_blocking(move || self.user_by_actor(&actor_id)).await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::sync::Arc;

    use arkret_bridge_runtime::DatabaseConfig;

    use super::*;

    fn sqlite_store(name: &str) -> Result<MessageStore> {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "arkret-bridge-messaging-{name}-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let db = DatabaseManager::connect(&DatabaseConfig {
            url: format!("sqlite://{}", path.display()),
            pool_size: 1,
        })?;
        MessageStore::new(Arc::new(db))
    }

    #[test]
    fn app_message_for_event_preserves_channel_and_message_id() {
        let store = sqlite_store("message-target").unwrap();
        store
            .record_message(
                "channel-1",
                "app-message-1",
                "sender-1",
                "ak:event:AcuTkvesoi9I-a82lRObr46_TuorpNOfeSLt8XCCajYY",
                "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO",
            )
            .unwrap();

        let mapping = store
            .app_message_for_event("ak:event:AcuTkvesoi9I-a82lRObr46_TuorpNOfeSLt8XCCajYY")
            .unwrap()
            .expect("mapping");
        assert_eq!(mapping.app_channel_id, "channel-1");
        assert_eq!(mapping.app_message_id, "app-message-1");
    }

    #[test]
    fn ghost_provision_preparation_preserves_first_signed_bytes() {
        let store = sqlite_store("ghost-provision").unwrap();
        assert_eq!(store.prepared_ghost_provision("tuple-1").unwrap(), None);
        assert_eq!(
            store
                .prepare_ghost_provision("tuple-1", "{\"event\":\"first\"}")
                .unwrap(),
            "{\"event\":\"first\"}"
        );
        assert_eq!(
            store
                .prepare_ghost_provision("tuple-1", "{\"event\":\"different\"}")
                .unwrap(),
            "{\"event\":\"first\"}"
        );
        assert_eq!(
            store
                .prepared_ghost_provision("tuple-1")
                .unwrap()
                .as_deref(),
            Some("{\"event\":\"first\"}")
        );
    }
}

/// DB-backed [`AppletResolver`] answering the arkret server's actor/realm probes
/// from the messaging mapping tables.
pub(crate) struct MessageResolver {
    pub(crate) store: Arc<MessageStore>,
}

impl AppletResolver for MessageResolver {
    fn resolve_actor(&self, actor_id: &str) -> Option<ResolvedActor> {
        let row = self.store.user_by_actor(actor_id).ok().flatten()?;
        Some(ResolvedActor {
            actor_id: row.arkret_actor_id,
            display_name: row.display_name,
            external_ref: Some(arkret::ExternalRef {
                protocol: row.protocol,
                external_id: row.external_user_id,
                instance_id: Some(row.tenant),
                display_name: None,
                url: None,
            }),
        })
    }

    fn resolve_realm(&self, realm_id_or_alias: &str) -> Option<ResolvedRealm> {
        let row = self
            .store
            .channel_by_realm_or_alias(realm_id_or_alias)
            .ok()
            .flatten()?;
        Some(ResolvedRealm {
            realm_id: row.arkret_realm_id,
            title: row.portal_alias,
            external_ref: Some(arkret::ExternalRef {
                protocol: "messaging".to_owned(),
                external_id: row.app_channel_id,
                instance_id: None,
                display_name: None,
                url: None,
            }),
        })
    }
}
