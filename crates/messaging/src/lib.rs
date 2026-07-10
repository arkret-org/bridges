//! Messaging helper layer for chat/social Arkret Applet bridges.
//!
//! This crate sits on top of `arkret-bridge-runtime`. It owns the
//! message-shaped contract shared by the social bridge adapters:
//!
//! - app channel/message/user mapping tables (location ↔ `(realm_id, strand_id)` per
//!   applet-integration §10.1),
//! - spec-shaped `ak.message.create` payload assembly (`{strand_id, track_name, content,
//!   blob_refs}`) and parsing,
//! - portal strand acquisition/creation (`ak.strand.create`),
//! - `MessageBridge` and `run_message_bridge`,
//! - `external_ref` provenance for upstream channel/user/message ids.

mod calendar;
mod content;
mod ghost;
mod media;
mod models;
mod schema;
mod store;
mod token;
mod types;
pub mod webhook;

use std::sync::Arc;
use std::time::Duration;

pub use arkret::models::EphemeralEnvelope;
use arkret::{
    AppletBridgeErrorBuilder, AppletBridgeErrorVisibility, ContentBlock, Did, Event, EventId,
    MessageRedactPayload, RealmId,
};
pub use arkret_bridge_runtime as runtime;
use arkret_bridge_runtime::app::{BridgeApp, BridgeContext};
use arkret_bridge_runtime::db::{DbReplayGuardStore, DbTokenStore};
use arkret_bridge_runtime::{
    BridgeError, MessageDirection, ReplayGuardStore, Result, TokenCache, TokenStore,
    record_bridge_message, redact_sensitive_url_values,
};
use async_trait::async_trait;
pub use calendar::{
    CALENDAR_EVENT_PROFILE, CalendarMapError, bridge_calendar_schedule_fields, bridge_rsvp_payload,
};
pub use content::{
    extract_attachment, extract_plain_body, extract_strand_id, media_content_block,
    text_content_block,
};
use ghost::{
    bridge_error_class, bridge_error_code, bridge_protocol, bridge_tenant, create_portal_strand,
    external_id_object_ref_digest, external_ref_for_delete, external_ref_for_message,
    find_existing_portal_strand, message_mapping_channel_key, normalized_external_id,
    portal_location_ref, provision_ghost_actor, require_nonempty_ref,
};
pub use media::{
    HttpInboundMediaFetcher, InboundMediaFetchPolicy, InboundMediaFetcher, InboundMediaReference,
};
pub use runtime::salvo;
use serde_json::{Value, json};
use store::MessageResolver;
pub use store::{ChannelRealmMapping, MessageMapping, MessageStore, UserMapping};
pub use token::{VendorTokenCheck, fetch_vendor_token};
pub use types::{
    AppDeleteOutcome, AppDeleteReason, AppMessageRef, Attachment, DEFAULT_GRAPH_API_VERSION,
    DEFAULT_MEDIA_MIME, DownloadedMedia, InboundAppDelete, InboundAppMessage,
    MAX_EXTERNAL_MEDIA_BYTES, MessageBridgeCapabilities, OutboundAppMessage, SenderRenderStyle,
};

// Not a `ak.`-prefixed id: the `ak.` namespace is reserved for spec-registered
// protocol objects/operations/schemas. This is a bridge-private (applet-side)
// provenance schema id, so it uses a reverse-domain product prefix to avoid
// colliding with any future spec-defined messaging external_ref schema.
pub(crate) const EXTERNAL_REF_SCHEMA: &str = "org.arkret.bridge.external_ref.messaging.v1";
pub(crate) const MESSAGE_MAPPING_KEY_SEPARATOR: char = '\u{1f}';

pub fn json_scalar_id_string(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    } else if let Some(n) = value.as_i64() {
        Some(n.to_string())
    } else {
        value.as_u64().map(|n| n.to_string())
    }
}

/// The inbound (arkret → app) event kinds this messaging bridge consumes, used
/// for capability enforcement (BRG-01-009): the runtime rejects any pushed event
/// whose kind is not listed. `MessageAdapter::on_arkret_event` handles exactly
/// message creation and redaction.
const BRIDGE_HANDLED_EVENT_KINDS: [&str; 2] = ["ak.message.create", "ak.message.redact"];

/// The strand track bridged messages write into. Applet-integration §10.1
/// requires bridge messages to use the `discussion` track; the v1
/// `message_create_payload.track_name` schema constrains it to that value.
pub(crate) const PORTAL_STRAND_TRACK: &str = "discussion";

/// Page size for the §10.1 step-2 projection scan over realm history.
pub(crate) const PORTAL_STRAND_SCAN_PAGE_LIMIT: u32 = 200;
/// Page cap for the §10.1 step-2 projection scan (bounds startup cost on large
/// realms; a fresh portal realm resolves in one page).
pub(crate) const PORTAL_STRAND_SCAN_MAX_PAGES: usize = 25;

pub(crate) fn redaction_payload_for_app_delete(
    target_event_id: &str,
    reason: AppDeleteReason,
) -> Result<Option<MessageRedactPayload>> {
    let Some(reason) = reason.redaction_reason() else {
        return Ok(None);
    };
    Ok(Some(MessageRedactPayload {
        message_id: None,
        target_ref: None,
        event_id: None,
        target_event_id: Some(EventId::new(target_event_id.to_owned())?),
        track_name: None,
        reason: Some(reason.to_owned()),
        preserve: None,
    }))
}

/// Runtime context handed to a [`MessageBridge`].
pub struct MessageContext {
    inner: Arc<BridgeContext>,
    store: Arc<MessageStore>,
    /// Shared durable store backing every [`webhook::ReplayWindow`] this bridge
    /// builds (bridge contract G-4 replay guards survive restarts and are
    /// shared across replicas).
    replay_guard: Arc<dyn ReplayGuardStore>,
    /// Shared durable store backing every [`TokenCache`] this bridge builds
    /// (one live vendor token across replicas).
    token_store: Arc<dyn TokenStore>,
    pub http: reqwest::Client,
}

impl MessageContext {
    fn new(inner: Arc<BridgeContext>, store: Arc<MessageStore>) -> Self {
        let http = inner.http.clone();
        let replay_guard: Arc<dyn ReplayGuardStore> =
            Arc::new(DbReplayGuardStore::new(inner.db.clone()));
        let token_store: Arc<dyn TokenStore> = Arc::new(DbTokenStore::new(inner.db.clone()));
        Self {
            inner,
            store,
            replay_guard,
            token_store,
            http,
        }
    }

    pub fn store(&self) -> &MessageStore {
        &self.store
    }

    pub fn core(&self) -> &Arc<BridgeContext> {
        &self.inner
    }

    /// Build a durable webhook replay window (bridge contract G-4) with the
    /// given acceptance TTL, backed by the shared bridge database so the guard
    /// holds across restarts and horizontally scaled replicas.
    pub fn replay_window(&self, ttl: Duration) -> Arc<webhook::ReplayWindow> {
        Arc::new(webhook::ReplayWindow::new(self.replay_guard.clone(), ttl))
    }

    /// Build a persistent vendor access-token cache under `cache_key` (unique
    /// per purpose, e.g. `wechat_access_token`), backed by the shared bridge
    /// database so all replicas observe the most recently fetched token.
    pub fn token_cache(&self, cache_key: &str) -> TokenCache {
        TokenCache::new(self.token_store.clone(), cache_key)
    }

    /// Emit a `ak.applet.bridge_error` Event for a failed inbound (app → arkret)
    /// submission so the failure is durable and visible to realm admins, rather
    /// than only logged (applet-integration §14 SHOULD, §16 bindings;
    /// `ak.profile.applet_bridge.v1` "bridge error event visibility" test item).
    ///
    /// Per §16 the bridge MUST NOT inline unauthorized external plaintext: the
    /// payload binds only the external `protocol`/`network_id`/`location_id` and
    /// the external event id (used as `failed_transaction_ref`) — never the
    /// message body. When the app channel has no realm mapping yet (provisioning
    /// or mapping gap) there is no realm to bind the error to, so emission is
    /// skipped (the failure is still logged by the caller). This is best-effort:
    /// a failure to emit the bridge error must not mask the original failure.
    pub async fn report_inbound_bridge_error(
        &self,
        msg: &InboundAppMessage,
        error: &BridgeError,
        retriable: bool,
    ) {
        // §16: no realm to bind to ⇒ nothing durable to emit. (Provisioning /
        // mapping-gap failures fall here; the caller already logged them.)
        let realm_id = match self
            .store
            .clone()
            .portal_for_channel_async(msg.app_channel.clone())
            .await
        {
            Ok(Some(row)) => row.arkret_realm_id,
            Ok(None) => return,
            Err(lookup_err) => {
                tracing::warn!(error = %lookup_err, "bridge_error realm lookup failed; skipping emit");
                return;
            }
        };
        if let Err(emit_err) = self
            .emit_bridge_error(&realm_id, msg, error, retriable)
            .await
        {
            tracing::warn!(error = %emit_err, "failed to emit ak.applet.bridge_error event");
        }
    }

    async fn emit_bridge_error(
        &self,
        realm_id: &str,
        msg: &InboundAppMessage,
        error: &BridgeError,
        retriable: bool,
    ) -> Result<()> {
        let edge = &self.inner.edge;
        let realm = RealmId::new(realm_id.to_owned())?;
        // `failed_transaction_ref` points at the source external event, never the
        // body. external_ref carries only network coordinates (no plaintext).
        let failed_ref = external_id_object_ref_digest(&msg.app_message_id);
        let external_ref = portal_location_ref(&self.inner.config, &msg.app_channel);
        let builder = AppletBridgeErrorBuilder::new(
            realm.clone(),
            edge.applet_id().to_owned(),
            edge.service_did().clone(),
            failed_ref,
            bridge_error_class(error),
            bridge_error_code(error),
            retriable,
            AppletBridgeErrorVisibility::RealmAdmins,
        )
        .with_external_ref(external_ref);
        edge.submit_bridge_error(&realm, builder).await?;
        Ok(())
    }

    /// Collapse the three-step inbound-failure audit shared by the gateway /
    /// long-poll bridges (Discord, Telegram, Slack, Zulip): classify retriability,
    /// `warn!`-log the failure with a bridge label, and best-effort emit a durable
    /// `ak.applet.bridge_error`. Returns whether the failure is retriable so each
    /// adapter can signal its own upstream in the bridge-specific way (teloxide
    /// `RequestError::Io`, Slack ack suppression, Zulip poll break). The pure
    /// webhook bridges reuse the equivalent collapse inside [`webhook::submit`].
    pub async fn report_inbound_failure(
        &self,
        label: &str,
        inbound: &InboundAppMessage,
        error: &BridgeError,
    ) -> bool {
        let retriable = error.is_retriable();
        tracing::warn!(%error, bridge = label, retriable, "inbound bridge submission failed");
        self.report_inbound_bridge_error(inbound, error, retriable)
            .await;
        retriable
    }

    /// Record a deterministic inbound media rejection for adapters that have
    /// not implemented a safe platform media download path yet. Long-poll
    /// adapters may use the returned retriable classification; webhook adapters
    /// can ignore it when they intentionally accept-with-audit.
    pub async fn report_unsupported_inbound_media(
        &self,
        label: &str,
        app_channel: impl Into<String>,
        app_user: impl Into<String>,
        app_message_id: impl Into<String>,
        media_kind: impl AsRef<str>,
    ) -> bool {
        let inbound = InboundAppMessage {
            app_channel: app_channel.into(),
            app_user: app_user.into(),
            app_message_id: app_message_id.into(),
            body: String::new(),
        };
        let error = BridgeError::App(format!(
            "{label} inbound media is not supported yet: {}",
            media_kind.as_ref()
        ));
        self.report_inbound_failure(label, &inbound, &error).await
    }

    /// Emit a `ak.applet.bridge_error` Event for a failed outbound (arkret → app)
    /// delivery so the failure is durable and visible to realm admins, mirroring
    /// the inbound path ([`MessageContext::report_inbound_bridge_error`]). The
    /// failed arkret `event_id` is the `failed_transaction_ref`; `external_ref`
    /// binds only the target external location (no message body). Best-effort: a
    /// failure to emit must not mask the original delivery failure.
    pub async fn report_outbound_bridge_error(
        &self,
        realm_id: &str,
        app_channel: &str,
        failed_event_id: &str,
        error: &BridgeError,
        retriable: bool,
    ) {
        if let Err(emit_err) = self
            .emit_outbound_bridge_error(realm_id, app_channel, failed_event_id, error, retriable)
            .await
        {
            tracing::warn!(error = %emit_err, "failed to emit outbound ak.applet.bridge_error event");
        }
    }

    async fn emit_outbound_bridge_error(
        &self,
        realm_id: &str,
        app_channel: &str,
        failed_event_id: &str,
        error: &BridgeError,
        retriable: bool,
    ) -> Result<()> {
        let edge = &self.inner.edge;
        let realm = RealmId::new(realm_id.to_owned())?;
        let external_ref = portal_location_ref(&self.inner.config, app_channel);
        let builder = AppletBridgeErrorBuilder::new(
            realm.clone(),
            edge.applet_id().to_owned(),
            edge.service_did().clone(),
            failed_event_id.to_owned(),
            bridge_error_class(error),
            bridge_error_code(error),
            retriable,
            AppletBridgeErrorVisibility::RealmAdmins,
        )
        .with_external_ref(external_ref);
        edge.submit_bridge_error(&realm, builder).await?;
        Ok(())
    }

    /// Upload bytes to arkret blob storage, returning the blob_ref string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        self.inner.edge.upload_blob(bytes, mime).await
    }

    /// Download a arkret blob by its blob_ref string.
    pub async fn download_blob(&self, blob_ref: &str) -> Result<Vec<u8>> {
        self.inner.edge.download_blob(blob_ref).await
    }

    /// Download app-hosted media with HTTPS, host allow-list and a hard byte
    /// cap. Use this for all inbound media fetches before uploading to Arkret blob
    /// storage.
    pub async fn download_external_media(
        &self,
        url: &str,
        bearer_token: Option<&str>,
        allowed_hosts: &[&str],
    ) -> Result<DownloadedMedia> {
        let reference = InboundMediaReference {
            url: url.to_owned(),
            bearer_token: bearer_token.map(str::to_owned),
            allowed_hosts: allowed_hosts
                .iter()
                .map(|host| (*host).to_owned())
                .collect(),
        };
        HttpInboundMediaFetcher::new(self.http.clone())
            .fetch(&reference, InboundMediaFetchPolicy::default())
            .await
    }

    /// Forward one piece of inbound external media into arkret with the shared
    /// skeleton: download (https + host allowlist + byte cap) → MIME fallback
    /// (`mime_hint` → download `Content-Type` → [`DEFAULT_MEDIA_MIME`]) → blob
    /// upload → [`Attachment`] assembly → [`Self::submit_media_message`].
    ///
    /// On any step failing, the shared inbound-failure audit
    /// ([`Self::report_inbound_failure`]: warn log + best-effort durable
    /// `ak.applet.bridge_error`) has already run before the `Err` is returned —
    /// callers only translate `err.is_retriable()` into their platform's retry
    /// signal. Bridges keep only the platform-specific "resolve the download
    /// URL / credentials" step (BRG-DRY-02).
    pub async fn forward_external_media(
        &self,
        label: &str,
        inbound: InboundAppMessage,
        request: ExternalMediaRequest<'_>,
    ) -> Result<String> {
        let result = self.forward_external_media_inner(&inbound, request).await;
        if let Err(err) = &result {
            self.report_inbound_failure(label, &inbound, err).await;
        }
        result
    }

    async fn forward_external_media_inner(
        &self,
        inbound: &InboundAppMessage,
        request: ExternalMediaRequest<'_>,
    ) -> Result<String> {
        let media = self
            .download_external_media(request.url, request.bearer_token, request.allowed_hosts)
            .await?;
        let mime = request
            .mime_hint
            .or(media.content_type)
            .unwrap_or_else(|| DEFAULT_MEDIA_MIME.to_owned());
        let blob_ref = self.upload_blob(&media.bytes, &mime).await?;
        let attachment = Attachment {
            blob_ref,
            media_type: Some(mime),
            filename: request.filename,
            size: Some(media.bytes.len() as u64),
            // Left empty: `submit_media_message` fills the caption from the
            // inbound body when the platform delivered one.
            caption: String::new(),
        };
        self.submit_media_message(inbound.clone(), attachment).await
    }

    /// Resolve the portal strand for an app channel following the §10.1
    /// acquisition order: persisted mapping → projection scan over the portal
    /// realm (match by external location) → `ak.strand.create`. The result is
    /// cached in the channel↔realm mapping. Serialized per channel so
    /// concurrent first messages cannot double-create.
    pub async fn ensure_portal_strand(&self, app_channel: &str, realm_id: &str) -> Result<String> {
        let channel_key = message_mapping_channel_key(&self.inner.config, app_channel);
        let queue_key = format!("portal_strand{MESSAGE_MAPPING_KEY_SEPARATOR}{channel_key}");
        self.inner
            .queue
            .run(&queue_key, || {
                let edge = self.inner.edge.clone();
                let store = self.store.clone();
                let config = self.inner.config.clone();
                let app_channel = app_channel.to_owned();
                let realm_id = realm_id.to_owned();
                async move {
                    // §10.1 step 1: the persisted location ↔ (realm_id, strand_id)
                    // mapping.
                    let row = store
                        .clone()
                        .portal_for_channel_async(app_channel.clone())
                        .await?;
                    let alias = row.as_ref().and_then(|row| row.portal_alias.clone());
                    if let Some(row) = row
                        && row.arkret_realm_id == realm_id
                        && let Some(strand_id) = row
                            .portal_strand_id
                            .filter(|strand_id| !strand_id.trim().is_empty())
                    {
                        return Ok::<String, BridgeError>(strand_id);
                    }
                    let location = portal_location_ref(&config, &app_channel);
                    // §10.1 step 2: look for an existing portal strand.
                    let strand_id =
                        match find_existing_portal_strand(&edge, &realm_id, &location).await? {
                            Some(strand_id) => strand_id,
                            // §10.1 step 3: create it.
                            None => {
                                create_portal_strand(
                                    &edge,
                                    &app_channel,
                                    alias.as_deref(),
                                    &realm_id,
                                    &location,
                                )
                                .await?
                            }
                        };
                    store
                        .set_channel_portal_strand_async(app_channel, strand_id.clone())
                        .await?;
                    Ok(strand_id)
                }
            })
            .await
    }

    /// Resolve the external channel mapped to a portal Realm. Ephemeral signals
    /// use this reverse mapping without creating durable message history.
    pub async fn app_channel_for_realm(&self, realm_id: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .clone()
            .channel_for_realm_async(realm_id.to_owned())
            .await?
            .map(|mapping| mapping.app_channel_id))
    }

    /// The metrics `bridge` label for this context (the configured bridge id).
    fn metrics_bridge_label(&self) -> &str {
        &self.inner.config.bridge.bridge_id
    }

    /// Record the outcome of one bridged message flow for `/metrics`.
    fn record_message_metric(&self, direction: MessageDirection, result: &Result<impl Sized>) {
        let label = if result.is_ok() { "ok" } else { "error" };
        record_bridge_message(self.metrics_bridge_label(), direction, label);
    }

    /// Submit an inbound text message as a `ak.message.create` event.
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String> {
        let content = text_content_block(&msg.body)?;
        let result = self.submit_content(&msg, content, Vec::new()).await;
        self.record_message_metric(MessageDirection::Inbound, &result);
        result
    }

    /// Submit an inbound media message. The `attachment` must already reference a
    /// blob uploaded via [`MessageContext::upload_blob`]; `msg.body` becomes the
    /// caption when non-empty.
    pub async fn submit_media_message(
        &self,
        msg: InboundAppMessage,
        mut attachment: Attachment,
    ) -> Result<String> {
        if attachment.caption.is_empty() {
            attachment.caption = msg.body.clone();
        }
        let content = media_content_block(&attachment)?;
        let result = self
            .submit_content(&msg, content, vec![attachment.blob_ref.clone()])
            .await;
        self.record_message_metric(MessageDirection::InboundMedia, &result);
        result
    }

    /// Submit an inbound app-side explicit delete/recall as a Arkret message
    /// redaction. Expiry, retention and bridge-drop signals are not redactions
    /// and are returned as ignored outcomes without minting protocol events.
    ///
    /// Status (BRG-HYG-002): this inbound-delete link is complete and unit-tested
    /// but **no adapter constructs an [`InboundAppDelete`] yet**. Wiring it needs
    /// a platform delete event that carries the *deleting actor* (required here
    /// for ghost mapping) and the relevant intent subscription; tracked in
    /// `_bridges_todos.md`.
    pub async fn submit_app_delete(&self, delete: InboundAppDelete) -> Result<AppDeleteOutcome> {
        if delete.reason.redaction_reason().is_none() {
            return Ok(AppDeleteOutcome::Ignored {
                reason_code: delete.reason.ignored_reason_code(),
            });
        }
        let external_target_event_id = normalized_external_id(&delete.app_message_id);
        if external_target_event_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_message_id is required for delete target lookup".into(),
            ));
        }
        let external_actor_id = normalized_external_id(&delete.app_user);
        if external_actor_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_user is required for delete actor mapping".into(),
            ));
        }
        let realm = self
            .store
            .clone()
            .portal_for_channel_async(delete.app_channel.clone())
            .await?
            .map(|row| row.arkret_realm_id)
            .ok_or_else(|| {
                BridgeError::App(format!(
                    "channel {} has no realm mapping; cannot forward app delete",
                    delete.app_channel
                ))
            })?;
        let mapping_channel_key =
            message_mapping_channel_key(&self.inner.config, &delete.app_channel);
        self.inner
            .queue
            .run(&mapping_channel_key, || {
                let edge = self.inner.edge.clone();
                let store = self.store.clone();
                let config = self.inner.config.clone();
                let mapping_channel_key = mapping_channel_key.clone();
                let external_target_event_id = external_target_event_id.clone();
                let external_actor_id = external_actor_id.clone();
                let realm_for_submit = realm.clone();
                let delete = delete.clone();
                async move {
                    let Some(target_event_id) = store
                        .clone()
                        .event_for_channel_message_target_async(
                            mapping_channel_key.clone(),
                            external_target_event_id.clone(),
                        )
                        .await?
                    else {
                        return Ok::<AppDeleteOutcome, BridgeError>(AppDeleteOutcome::Ignored {
                            reason_code: "app_delete_unmapped_target",
                        });
                    };
                    let protocol = bridge_protocol(&config);
                    let tenant = bridge_tenant(&config);
                    let mapping = match store
                        .clone()
                        .ghost_actor_for_app_user_async(
                            protocol.clone(),
                            tenant.clone(),
                            external_actor_id.clone(),
                        )
                        .await?
                    {
                        Some(mapping) => mapping,
                        None => {
                            let provisioned = provision_ghost_actor(
                                &edge,
                                &config,
                                &protocol,
                                &tenant,
                                &external_actor_id,
                                Some(&external_actor_id),
                                &realm_for_submit,
                            )
                            .await?;
                            let actor_id = provisioned.ghost_actor_id.to_string();
                            let display_name = provisioned
                                .display_name
                                .as_deref()
                                .or(Some(external_actor_id.as_str()));
                            store
                                .clone()
                                .upsert_user_async(
                                    protocol.clone(),
                                    tenant.clone(),
                                    external_actor_id.clone(),
                                    actor_id,
                                    provisioned.profile_event_ref.clone(),
                                    provisioned.accountability_grant_ref.clone(),
                                    provisioned.authorization_ref.clone(),
                                    display_name.map(str::to_owned),
                                )
                                .await?;
                            store
                                .clone()
                                .ghost_actor_for_app_user_async(
                                    protocol.clone(),
                                    tenant.clone(),
                                    external_actor_id.clone(),
                                )
                                .await?
                                .ok_or_else(|| {
                                    BridgeError::Database(
                                        "ghost actor provisioning row was not persisted".into(),
                                    )
                                })?
                        }
                    };
                    require_nonempty_ref("profile_event_ref", &mapping.profile_event_ref)?;
                    require_nonempty_ref(
                        "accountability_grant_ref",
                        &mapping.accountability_grant_ref,
                    )?;
                    require_nonempty_ref("authorization_ref", &mapping.authorization_ref)?;
                    let actor = Did::new(mapping.arkret_actor_id)?;
                    let payload =
                        redaction_payload_for_app_delete(&target_event_id, delete.reason)?
                            .expect("delete reason was checked before queue submission");
                    let event_id = edge
                        .submit_redaction_with_external_ref_as(
                            &actor,
                            &realm_for_submit,
                            &target_event_id,
                            payload,
                            external_ref_for_delete(&config, &delete),
                            &mapping.authorization_ref,
                        )
                        .await?;
                    Ok(AppDeleteOutcome::Submitted {
                        event_id,
                        target_event_id,
                    })
                }
            })
            .await
    }

    /// Shared submit path: resolve the portal `(realm_id, strand_id)`, assemble
    /// the spec `message_create_payload`, attach provenance, submit on the
    /// per-channel serial queue, and record the message mapping.
    async fn submit_content(
        &self,
        msg: &InboundAppMessage,
        content: ContentBlock,
        blob_refs: Vec<String>,
    ) -> Result<String> {
        let external_event_id = normalized_external_id(&msg.app_message_id);
        if external_event_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_message_id is required for external event deduplication".into(),
            ));
        }

        let realm = self
            .store
            .clone()
            .portal_for_channel_async(msg.app_channel.clone())
            .await?
            .map(|row| row.arkret_realm_id)
            .ok_or_else(|| {
                BridgeError::App(format!(
                    "channel {} has no realm mapping; create an explicit channel-realm mapping",
                    msg.app_channel
                ))
            })?;
        // §10.1: the mapping unit for an external location is (realm_id,
        // strand_id) — resolve the portal strand before submitting.
        let strand_id = self.ensure_portal_strand(&msg.app_channel, &realm).await?;
        let payload = content::build_message_create_payload(&strand_id, content, blob_refs)?;

        let protocol = bridge_protocol(&self.inner.config);
        let tenant = bridge_tenant(&self.inner.config);
        let external_user_id = normalized_external_id(&msg.app_user);
        if external_user_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_user is required for ghost actor mapping".into(),
            ));
        }

        let mapping_channel_key = message_mapping_channel_key(&self.inner.config, &msg.app_channel);
        let event_id = self
            .inner
            .queue
            .run(&mapping_channel_key, || {
                let edge = self.inner.edge.clone();
                let store = self.store.clone();
                let config = self.inner.config.clone();
                let external_ref = external_ref_for_message(&config, msg);
                let mapping_channel_key = mapping_channel_key.clone();
                let external_event_id = external_event_id.clone();
                let protocol = protocol.clone();
                let tenant = tenant.clone();
                let external_user_id = external_user_id.clone();
                let realm_for_submit = realm.clone();
                let realm_for_record = realm.clone();
                async move {
                    if let Some(existing_event_id) = store
                        .clone()
                        .event_for_channel_message_async(
                            mapping_channel_key.clone(),
                            external_event_id.clone(),
                            external_user_id.clone(),
                        )
                        .await?
                    {
                        return Ok::<String, BridgeError>(existing_event_id);
                    }
                    let mapping = match store
                        .clone()
                        .ghost_actor_for_app_user_async(
                            protocol.clone(),
                            tenant.clone(),
                            external_user_id.clone(),
                        )
                        .await?
                    {
                        Some(mapping) => mapping,
                        None => {
                            let provisioned = provision_ghost_actor(
                                &edge,
                                &config,
                                &protocol,
                                &tenant,
                                &external_user_id,
                                Some(&external_user_id),
                                &realm_for_submit,
                            )
                            .await?;
                            let actor_id = provisioned.ghost_actor_id.to_string();
                            let display_name = provisioned
                                .display_name
                                .as_deref()
                                .or(Some(external_user_id.as_str()));
                            store
                                .clone()
                                .upsert_user_async(
                                    protocol.clone(),
                                    tenant.clone(),
                                    external_user_id.clone(),
                                    actor_id,
                                    provisioned.profile_event_ref.clone(),
                                    provisioned.accountability_grant_ref.clone(),
                                    provisioned.authorization_ref.clone(),
                                    display_name.map(str::to_owned),
                                )
                                .await?;
                            store
                                .clone()
                                .ghost_actor_for_app_user_async(
                                    protocol.clone(),
                                    tenant.clone(),
                                    external_user_id.clone(),
                                )
                                .await?
                                .ok_or_else(|| {
                                    BridgeError::Database(
                                        "ghost actor provisioning row was not persisted".into(),
                                    )
                                })?
                        }
                    };
                    require_nonempty_ref("profile_event_ref", &mapping.profile_event_ref)?;
                    require_nonempty_ref(
                        "accountability_grant_ref",
                        &mapping.accountability_grant_ref,
                    )?;
                    require_nonempty_ref("authorization_ref", &mapping.authorization_ref)?;
                    let actor = Did::new(mapping.arkret_actor_id)?;
                    let event_id = edge
                        .submit_with_external_ref_as(
                            &actor,
                            &realm_for_submit,
                            "ak.message.create",
                            payload,
                            external_ref,
                            &mapping.authorization_ref,
                        )
                        .await?;
                    store
                        .record_message_async(
                            mapping_channel_key,
                            external_event_id,
                            external_user_id,
                            event_id.clone(),
                            realm_for_record,
                        )
                        .await?;
                    Ok::<String, BridgeError>(event_id)
                }
            })
            .await?;
        Ok(event_id)
    }
}

/// Where to fetch external media and how to describe it; see
/// [`MessageContext::forward_external_media`].
pub struct ExternalMediaRequest<'a> {
    /// The https download URL.
    pub url: &'a str,
    /// Optional bearer token sent with the download request.
    pub bearer_token: Option<&'a str>,
    /// Host allowlist enforced on the download URL.
    pub allowed_hosts: &'a [&'a str],
    /// Platform-declared MIME type; preferred over the download response's
    /// `Content-Type` when present.
    pub mime_hint: Option<String>,
    /// Attachment filename, when the platform provides one.
    pub filename: Option<String>,
}

/// Send an outbound vendor API request, parse the JSON response, apply the
/// vendor-specific success predicate, and wrap every failure as
/// `BridgeError::App` with the message sensitive-value-redacted.
///
/// This collapses the `send → .json::<Value>() → success check → redacted error`
/// skeleton shared by the HTTP outbound bridges (Slack `ok==true`, Feishu/WeChat
/// `code/errcode==0`, Zulip `result=="success"`, …). The per-bridge differences
/// — the success flag key and the path the caller reads the message id from —
/// stay with the caller: `is_success` expresses the success rule, and the caller
/// extracts the id from the returned [`Value`]. `label` names the call for error
/// messages (e.g. `"Slack chat.postMessage"`).
pub async fn send_json_expect(
    request: reqwest::RequestBuilder,
    label: &str,
    is_success: impl Fn(&Value) -> bool,
) -> Result<Value> {
    let response = request.send().await.map_err(|e| {
        BridgeError::App(format!(
            "{label} request failed: {}",
            redact_sensitive_url_values(e.to_string())
        ))
    })?;
    let body: Value = response.json().await.map_err(|e| {
        BridgeError::App(format!(
            "{label} response parse failed: {}",
            redact_sensitive_url_values(e.to_string())
        ))
    })?;
    if !is_success(&body) {
        return Err(BridgeError::App(format!(
            "{label} returned an error: {}",
            redact_sensitive_url_values(body.to_string())
        )));
    }
    Ok(body)
}

/// Character cap applied to vendor error bodies quoted into error messages, so
/// a large (or hostile) error response cannot bloat logs or audit events.
const ERROR_BODY_SNIPPET_MAX_CHARS: usize = 2048;

/// Send an outbound vendor API request whose success signal is the **HTTP
/// status** (as opposed to a flag inside the JSON body — that family uses
/// [`send_json_expect`]), and return the parsed JSON response body.
///
/// One shared order for the whole family (BRG-DRY-01): send → check status —
/// on failure read the error body as text (works for non-JSON vendor errors),
/// truncate and redact it — then parse JSON only on success. `label` names the
/// call for error messages (e.g. `"WhatsApp send"`).
pub async fn send_json_expect_status(
    request: reqwest::RequestBuilder,
    label: &str,
) -> Result<Value> {
    let response = request.send().await.map_err(|e| {
        BridgeError::App(format!(
            "{label} request failed: {}",
            redact_sensitive_url_values(e.to_string())
        ))
    })?;
    let status = response.status();
    if !status.is_success() {
        let detail: String = response
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(ERROR_BODY_SNIPPET_MAX_CHARS)
            .collect();
        return Err(BridgeError::App(format!(
            "{label} failed status={status}: {}",
            redact_sensitive_url_values(detail)
        )));
    }
    let body: Value = response.json().await.map_err(|e| {
        BridgeError::App(format!(
            "{label} response parse failed (status={status}): {}",
            redact_sensitive_url_values(e.to_string())
        ))
    })?;
    Ok(body)
}

#[async_trait]
pub trait MessageBridge: Send + Sync + 'static {
    fn name(&self) -> &str;

    /// Static adapter capabilities. The default is intentionally conservative:
    /// text-only bridges get a shared outbound attachment downgrade instead of
    /// receiving an attachment they would silently ignore.
    fn capabilities(&self) -> MessageBridgeCapabilities {
        MessageBridgeCapabilities::default()
    }

    /// The app-side receive loop. Pure webhook bridges (whose inbound path is the
    /// salvo `webhook_router`) can rely on the default keep-alive loop and only
    /// need to override `webhook_router`. Gateway / long-poll bridges (Discord,
    /// Telegram, Slack, Zulip) override this with their own connection loop.
    async fn run(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Result<()> {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef>;

    /// Forward a Arkret message redaction as an app-side deletion. The driver
    /// (`on_arkret_event`) already resolves the target `app_message_id` and
    /// invokes this with the channel/message pair most app delete APIs require;
    /// the default is a structured rejection so an unsupported adapter can
    /// never acknowledge a deletion it did not perform.
    async fn redact_in_app(
        &self,
        _ctx: Arc<MessageContext>,
        _app_channel: &str,
        _app_message_id: &str,
    ) -> Result<()> {
        Err(BridgeError::App(
            "outbound deletion is not supported by this adapter".to_owned(),
        ))
    }

    /// Handle an ephemeral signal (typing/presence/receipts/call-signal) pushed
    /// alongside events, as the SDK [`EphemeralEnvelope`] wire type; defaults to
    /// a structured rejection. Ephemeral rejection is logged by the consumer
    /// and never converted into a durable Event.
    async fn on_ephemeral(
        &self,
        _ctx: Arc<MessageContext>,
        _ephemeral: EphemeralEnvelope,
    ) -> Result<()> {
        Err(BridgeError::App(
            "ephemeral forwarding is not supported by this adapter".to_owned(),
        ))
    }

    /// Whether this bridge's inbound surface is the salvo `webhook_router`. When
    /// true, the runtime treats a `None` from [`Self::webhook_router`] (e.g. a
    /// required body-signature key is missing) as a fatal misconfiguration and
    /// fails fast at startup, rather than running a "healthy" process that can
    /// never receive any inbound message (BRG-REL-001). Gateway / long-poll
    /// bridges (which override `run` and expose no public webhook plane) leave
    /// this `false`.
    fn expects_webhook_inbound(&self) -> bool {
        false
    }

    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        None
    }
}

struct MessageAdapter<M: MessageBridge> {
    user: Arc<M>,
    ctx: Arc<MessageContext>,
}

impl<M: MessageBridge> MessageAdapter<M> {
    async fn apply_outbound_capability_guard(
        &self,
        realm_id: &str,
        event_id: &str,
        out: &mut OutboundAppMessage,
    ) {
        if self.user.capabilities().outbound_native_attachments {
            return;
        }
        let Some(downgrade) = out.downgrade_attachment_to_text() else {
            return;
        };
        tracing::warn!(
            bridge = self.user.name(),
            realm = %realm_id,
            app_channel = %out.app_channel.as_str(),
            attachment_blob_ref = %downgrade.blob_ref.as_str(),
            attachment_filename = downgrade.filename.as_deref().unwrap_or("<none>"),
            attachment_media_type = downgrade.media_type.as_deref().unwrap_or("<unknown>"),
            attachment_size_bytes = ?downgrade.size,
            "outbound attachment downgraded to text because bridge lacks native attachment capability"
        );
        let error = BridgeError::App(downgrade.audit_message());
        self.ctx
            .report_outbound_bridge_error(realm_id, &out.app_channel, event_id, &error, false)
            .await;
    }
}

async fn sender_display_for_event(
    store: Arc<MessageStore>,
    actor_id: String,
    executed_by: Option<String>,
) -> Result<String> {
    let mut display = match store.user_by_actor_async(actor_id.clone()).await? {
        Some(row) => row
            .display_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(row.external_user_id),
        None => actor_id.clone(),
    };
    if let Some(executed_by) = executed_by
        && executed_by != actor_id
    {
        display = format!("{display} via {executed_by}");
    }
    Ok(display)
}

#[async_trait]
impl<M: MessageBridge> BridgeApp for MessageAdapter<M> {
    fn name(&self) -> &str {
        self.user.name()
    }

    async fn run(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Result<()> {
        self.user.clone().run(self.ctx.clone()).await
    }

    async fn on_arkret_event(&self, _ctx: Arc<BridgeContext>, event: Event) -> Result<()> {
        // Deletion forwarding (arkret -> app): a `ak.message.redact` that targets
        // an event we previously bridged is mapped to an app-side deletion via the
        // adapter's `redact_in_app`. Honors the `disable_deletion_forwarding`
        // switch.
        if event.kind == "ak.message.redact" {
            if self.ctx.core().config.bridge.disable_deletion_forwarding {
                return Ok(());
            }
            let Some(target) = event.redacts.as_ref() else {
                return Ok(());
            };
            let Some(mapping) = self
                .ctx
                .store
                .clone()
                .app_message_for_event_async(target.as_ref().to_owned())
                .await?
            else {
                return Ok(());
            };
            self.user
                .redact_in_app(
                    self.ctx.clone(),
                    &mapping.app_channel_id,
                    &mapping.app_message_id,
                )
                .await?;
            return Ok(());
        }
        if event.kind != "ak.message.create" {
            return Ok(());
        }
        // Loop prevention: skip events this bridge itself submitted (app ->
        // arkret), which the server echoes back. Only signature-covered fields
        // are consulted: every delegated ghost event this bridge submits carries
        // `executed_by = service_did` plus signed Applet provenance, and service
        // actor events are authored by the service DID itself.
        // Both checks are independent of local DB state, so a server push
        // racing ahead of our own mapping write cannot bypass them.
        if event.executed_by.as_ref() == Some(self.ctx.core().edge.service_did()) {
            return Ok(());
        }
        if &event.actor_id == self.ctx.core().edge.service_did() {
            return Ok(());
        }
        let event_id = event.event_id.to_string();
        if self
            .ctx
            .store
            .clone()
            .app_message_for_event_async(event_id.clone())
            .await?
            .is_some()
        {
            return Ok(());
        }
        let realm_id = event.realm_id.to_string();
        let Some(channel_realm) = self
            .ctx
            .store
            .clone()
            .channel_for_realm_async(realm_id.clone())
            .await?
        else {
            tracing::debug!(realm = %realm_id, "realm has no channel mapping, dropping");
            return Ok(());
        };
        let channel = channel_realm.app_channel_id.clone();
        // §10.1: the external location maps to (realm_id, strand_id), not the
        // bare realm — only messages on the portal strand cross the bridge.
        let portal_strand = match channel_realm
            .portal_strand_id
            .filter(|f| !f.trim().is_empty())
        {
            Some(strand_id) => strand_id,
            None => self.ctx.ensure_portal_strand(&channel, &realm_id).await?,
        };
        let payload = event.as_message_create()?;
        if extract_strand_id(&payload) != portal_strand.as_str() {
            tracing::debug!(
                realm = %realm_id,
                portal_strand = %portal_strand,
                "message is not on the portal strand, dropping"
            );
            return Ok(());
        }
        let body = extract_plain_body(&payload)?;
        let attachment = extract_attachment(&payload)?;
        let sender_display = sender_display_for_event(
            self.ctx.store.clone(),
            event.actor_id.to_string(),
            event.executed_by.as_ref().map(ToString::to_string),
        )
        .await?;
        let mut out = OutboundAppMessage {
            app_channel: channel.clone(),
            sender_display,
            body,
            attachment,
        };
        self.apply_outbound_capability_guard(&realm_id, &event_id, &mut out)
            .await;
        let app_ref = match self.user.send_to_app(self.ctx.clone(), out).await {
            Ok(app_ref) => {
                record_bridge_message(
                    &self.ctx.core().config.bridge.bridge_id,
                    MessageDirection::Outbound,
                    "ok",
                );
                app_ref
            }
            Err(error) => {
                let retriable = error.is_retriable();
                record_bridge_message(
                    &self.ctx.core().config.bridge.bridge_id,
                    MessageDirection::Outbound,
                    "error",
                );
                tracing::warn!(
                    %error,
                    bridge = self.name(),
                    retriable,
                    realm = %realm_id,
                    app_channel = %channel,
                    "arkret → app delivery failed"
                );
                // Durable audit, symmetric with the inbound path. Best-effort.
                self.ctx
                    .report_outbound_bridge_error(&realm_id, &channel, &event_id, &error, retriable)
                    .await;
                // Propagate so the runtime's inbound consumer applies its retry /
                // dead-letter policy for retriable failures.
                return Err(error);
            }
        };
        let mapping_channel_key = message_mapping_channel_key(&self.ctx.core().config, &channel);
        let app_message_id = normalized_external_id(&app_ref.app_message_id);
        if app_message_id.is_empty() {
            tracing::debug!(
                realm = %realm_id,
                app_channel = %channel,
                "adapter returned no app message id; outbound mapping not recorded"
            );
        } else {
            self.ctx
                .store
                .clone()
                .record_message_async(
                    mapping_channel_key,
                    app_message_id,
                    event.actor_id.to_string(),
                    event.event_id.to_string(),
                    realm_id,
                )
                .await?;
        }
        Ok(())
    }

    async fn on_ephemeral(
        &self,
        _ctx: Arc<BridgeContext>,
        ephemeral: EphemeralEnvelope,
    ) -> Result<()> {
        self.user.on_ephemeral(self.ctx.clone(), ephemeral).await
    }

    fn expects_webhook_inbound(&self) -> bool {
        self.user.expects_webhook_inbound()
    }

    fn webhook_router(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Option<salvo::Router> {
        self.user.clone().webhook_router(self.ctx.clone())
    }
}

pub async fn run_message_bridge<M, F>(config: runtime::Config, factory: F) -> Result<()>
where
    M: MessageBridge,
    F: FnOnce(Arc<MessageContext>) -> Result<M>,
{
    runtime::run_bridge(config, move |core_ctx: Arc<BridgeContext>| {
        let store = Arc::new(MessageStore::new(core_ctx.db.clone())?);
        // Apply any static channel↔realm mappings from configuration so a bridge
        // is operable out of the box without hand-written SQL.
        for mapping in &core_ctx.config.mappings {
            store.upsert_channel_realm(
                &mapping.app_channel,
                &mapping.realm_id,
                mapping.alias.as_deref(),
            )?;
        }
        // Install DB-backed actor/realm resolution before the web service starts.
        core_ctx.set_resolver(Arc::new(MessageResolver {
            store: store.clone(),
        }));
        // Declare the inbound event kinds this messaging bridge consumes so the
        // applet handler rejects anything else as `capability_denied`
        // (BRG-01-009). `MessageAdapter::on_arkret_event` handles exactly these.
        core_ctx.set_handled_event_kinds(BRIDGE_HANDLED_EVENT_KINDS);
        let ctx = Arc::new(MessageContext::new(core_ctx, store));
        let user = Arc::new(factory(ctx.clone())?);
        Ok(MessageAdapter { user, ctx })
    })
    .await
}

/// Unified executable entry point for message-bridge binaries.
///
/// Factors out the per-bridge `main.rs` boilerplate: CLI parsing (a single
/// `--config` flag), [`runtime::Config::load`], logging init, strongly typed
/// `config.app` deserialization into `C`, and [`run_message_bridge`]. A bridge
/// binary reduces to its `AppConfig` definition plus a factory closure:
///
/// ```ignore
/// #[derive(serde::Deserialize)]
/// struct AppConfig { bot_token: String }
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     arkret_bridge_messaging::bridge_main("arkret <-> Example bridge", |app: AppConfig, _ctx| {
///         Ok(ExampleApp::new(app.bot_token))
///     })
///     .await
/// }
/// ```
pub async fn bridge_main<C, M, F>(about: &str, factory: F) -> anyhow::Result<()>
where
    C: serde::de::DeserializeOwned,
    M: MessageBridge,
    F: FnOnce(C, Arc<MessageContext>) -> Result<M>,
{
    // Use the invoked binary name (e.g. `arkret-bridge-slack`) for help/version
    // output instead of hardcoding one shared name here.
    let bin_name = std::env::args()
        .next()
        .as_deref()
        .map(std::path::Path::new)
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("arkret-bridge")
        .to_owned();
    let matches = clap::Command::new(bin_name)
        .version(env!("CARGO_PKG_VERSION"))
        .about(about.to_owned())
        .arg(
            clap::Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path (.yaml)")
                .default_value("config.yaml"),
        )
        .get_matches();
    let config_path = matches
        .get_one::<String>("config")
        .expect("config has a default value");

    let config = runtime::Config::load(config_path)?;
    runtime::logging::init(&config.logging);

    // `config.app` defaults to JSON null when the section is omitted; map that
    // to an empty object so serde reports each missing field by name.
    let app = match config.app.clone() {
        Value::Null => json!({}),
        value => value,
    };
    let app_config: C =
        serde_json::from_value(app).map_err(|e| anyhow::anyhow!("config.app is invalid: {e}"))?;

    run_message_bridge(config, move |ctx| factory(app_config, ctx)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
