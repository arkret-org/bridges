//! Ghost actor provisioning, external_ref provenance, and portal strand
//! acquisition helpers (applet-integration §9.1 / §10.1 / §16).

use std::sync::{Arc, OnceLock};

use arkret::{AppletId, Did, DidCoreId, EventKind, RealmId, StrandId, StrandTrack};
use arkret_bridge_runtime::{BridgeError, Result};
use arkret_models_collaboration::events_payloads::StrandCreatePayload;
use arkret_models_collaboration::objects::strand::Strand;
use arkret_models_integration::{
    AppletBridgeErrorClass, AppletManagedActorProvisionPayload, AppletManagedActorRole,
    GhostActorProvisionOutcome, GhostActorProvisionRequestBody, GhostExternalTuple,
};
use arkret_wire::{CommitStreamRef, StreamScanDirection, StreamScanRequest};
use serde::Serialize;
use serde_json::{Value, json};

use crate::store::MessageStore;
use crate::types::{InboundAppDelete, InboundAppMessage};
use crate::{
    EXTERNAL_REF_SCHEMA, MESSAGE_MAPPING_KEY_SEPARATOR, PORTAL_STRAND_SCAN_MAX_PAGES,
    PORTAL_STRAND_SCAN_PAGE_LIMIT, PORTAL_STRAND_TRACK, runtime,
};

static GHOST_PROVISION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

pub(crate) fn normalized_external_id(value: &str) -> String {
    value.trim().to_owned()
}

pub(crate) fn external_id_object_ref_digest(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let normalized = normalized_external_id(value);
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )
}

pub(crate) fn bridge_protocol(config: &runtime::Config) -> String {
    normalized_external_id(&config.bridge.bridge_id)
}

pub(crate) fn bridge_tenant(config: &runtime::Config) -> String {
    config
        .bridge
        .tenant_id
        .as_deref()
        .map(normalized_external_id)
        .filter(|tenant| !tenant.is_empty())
        .unwrap_or_else(|| normalized_external_id(config.arkret.service_did.as_str()))
}

/// Deterministic `Idempotency-Key` for ghost provisioning (required header per
/// the openapi binding; §9.1 keys server-side idempotency on
/// `(applet_id, protocol, tenant, external_user_id)`, so retries of the same
/// external user reuse the same key). Hashed to satisfy the 128-char bound.
fn ghost_provision_idempotency_key(
    applet_id: &str,
    realm_id: &str,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let material = [applet_id, realm_id, protocol, tenant, external_user_id]
        .join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string());
    format!(
        "ghost-provision-{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MessageExternalRef {
    schema: &'static str,
    protocol: String,
    tenant: String,
    external_channel: String,
    external_event_id: String,
    normalized_sender: String,
    source: String,
    app_channel: String,
    app_user: String,
    app_message_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DeleteExternalRef {
    schema: &'static str,
    protocol: String,
    tenant: String,
    external_channel: String,
    external_target_event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_event_id: Option<String>,
    normalized_actor: String,
    operation: &'static str,
    reason: &'static str,
    source: String,
    app_channel: String,
    app_message_id: String,
}

/// A completed Ghost provisioning: the Station's outcome plus the
/// resolvable Ghost DID this bridge authored for the same subject.
///
/// The two are bound by [`validate_ghost_provision_response`], which requires
/// the server's complete `ghost_actor_id` to match the authored Account,
/// including the DID principal and Station. Callers that need the resolvable form (event signing,
/// DID resolution) therefore carry it forward as verified evidence instead of
/// reconstructing a DID from the core id, which is never permitted.
pub(crate) struct ProvisionedGhostActor {
    pub(crate) did: Did,
    pub(crate) outcome: GhostActorProvisionOutcome,
}

/// Closed input handed to the Applet-managed identity authority that owns
/// Ghost WebVH key custody and the four-event authoring ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GhostProvisionAuthoringRequest {
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub actor_station_id: DidCoreId,
    pub realm_id: RealmId,
    pub external_ref: GhostExternalTuple,
    pub display_name: Option<String>,
}

/// Supplies one complete, caller-authored formal Ghost creation unit.
///
/// The provider is the only boundary allowed to own Ghost WebVH root keys,
/// complete method-history evidence, registration anchors, and the durable
/// exact-replay authoring ledger. A bridge without such a provider fails
/// closed; it never synthesizes a Ghost DID from the service identity or fabricates
/// provision/PCR Events locally.
#[async_trait::async_trait]
pub trait GhostProvisionRequestProvider: Send + Sync {
    async fn author_request(
        &self,
        request: &GhostProvisionAuthoringRequest,
    ) -> Result<GhostActorProvisionRequestBody>;
}

pub(crate) fn require_ghost_provision_provider(
    provider: Option<&Arc<dyn GhostProvisionRequestProvider>>,
) -> Result<&dyn GhostProvisionRequestProvider> {
    provider.map(AsRef::as_ref).ok_or_else(|| {
        BridgeError::Config(
            "Ghost provisioning requires an Applet-managed authoring provider".to_owned(),
        )
    })
}

// Ghost provisioning threads one distinct external-identity field per
// parameter; bundling them into a struct would let two of them be swapped
// at a call site without a type error.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn provision_ghost_actor(
    edge: &runtime::ArkretEdge,
    store: std::sync::Arc<MessageStore>,
    provider: &dyn GhostProvisionRequestProvider,
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
    display_name: Option<&str>,
    realm_id: &str,
) -> Result<ProvisionedGhostActor> {
    // Provisioning a first-seen external user is a multi-step unit: prepare the
    // request in the durable ledger, author it, then submit. Serialize it so two
    // concurrent deliveries for the same user cannot each start their own unit
    // before either has reached the ledger.
    let _provision_guard = GHOST_PROVISION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let external_ref = GhostExternalTuple {
        protocol: normalized_external_id(protocol),
        instance_id: normalized_external_id(tenant),
        external_id: normalized_external_id(external_user_id),
    };
    if external_ref.protocol.is_empty()
        || external_ref.instance_id.is_empty()
        || external_ref.external_id.is_empty()
    {
        return Err(BridgeError::App(
            "Ghost provision external identity tuple must be complete".to_owned(),
        ));
    }
    let authoring_request = GhostProvisionAuthoringRequest {
        applet_id: AppletId::new(config.arkret.applet_id.clone())?,
        service_id: edge.service_actor_id().clone(),
        actor_station_id: arkret::project_did_to_core_id(&config.arkret.trusted_server_did)?,
        realm_id: RealmId::new(realm_id.to_owned())?,
        external_ref,
        display_name: display_name.map(ToOwned::to_owned),
    };
    let idempotency_key = ghost_provision_idempotency_key(
        &config.arkret.applet_id,
        realm_id,
        protocol,
        tenant,
        external_user_id,
    );
    let request_json = match store
        .clone()
        .prepared_ghost_provision_async(idempotency_key.clone())
        .await?
    {
        Some(request_json) => request_json,
        None => {
            let request = provider.author_request(&authoring_request).await?;
            let _ = validate_authored_ghost_request(&authoring_request, &request, edge)?;
            let request_json = serde_json::to_string(&request).map_err(|error| {
                BridgeError::App(format!("Ghost provision encode failed: {error}"))
            })?;
            store
                .prepare_ghost_provision_async(idempotency_key.clone(), request_json)
                .await?
        }
    };
    let request: GhostActorProvisionRequestBody =
        serde_json::from_str(&request_json).map_err(|error| {
            BridgeError::Database(format!("stored Ghost provision invalid: {error}"))
        })?;
    let ghost_actor_id = validate_authored_ghost_request(&authoring_request, &request, edge)?;
    let response: GhostActorProvisionOutcome = edge
        .client()
        .ghost_actor_provision(&config.arkret.applet_id, &idempotency_key, &request)
        .await?;
    let requested_actor = arkret::ActorId::account(arkret::AccountId::new(
        arkret::project_did_to_core_id(&ghost_actor_id)?,
        authoring_request.actor_station_id.clone(),
    ));
    let outcome = validate_ghost_provision_response(&requested_actor, response)?;
    Ok(ProvisionedGhostActor {
        did: ghost_actor_id,
        outcome,
    })
}

fn validate_authored_ghost_request(
    expected: &GhostProvisionAuthoringRequest,
    request: &GhostActorProvisionRequestBody,
    edge: &runtime::ArkretEdge,
) -> Result<Did> {
    request
        .authoring_request
        .validate_bindings()
        .map_err(|error| {
            BridgeError::Arkret(format!("invalid Ghost authoring request: {error}"))
        })?;
    let basis = request.authoring_basis().ok_or_else(|| {
        BridgeError::Arkret("Ghost authoring provider returned a non-Ghost basis".to_owned())
    })?;
    if basis.applet_id != expected.applet_id
        || basis.service_id != expected.service_id
        || basis.target_station_id != expected.actor_station_id
        || basis.effective_scope
            != (arkret::ScopeRef::Realm {
                realm_id: expected.realm_id.clone(),
            })
        || basis.external_ref != expected.external_ref
        || basis.display_name != expected.display_name
    {
        return Err(BridgeError::Arkret(
            "Ghost authoring provider returned a request for different coordinates".to_owned(),
        ));
    }
    request.validate()?;
    if request.existing_managed_actor.is_some() {
        return edge.reused_ghost_did(request);
    }
    request
        .managed_actor_bundle
        .as_ref()
        .ok_or_else(|| BridgeError::Arkret("Ghost creation lacks its authoring bundle".into()))?
        .validate_bindings(&request.authoring_request)?;
    let payload: AppletManagedActorProvisionPayload =
        request.managed_actor_provision_payload().map_err(|error| {
            BridgeError::Arkret(format!("invalid managed-actor provision: {error}"))
        })?;
    payload.validate().map_err(|error| {
        BridgeError::Arkret(format!("invalid managed-actor provision payload: {error}"))
    })?;
    if payload.actor_role != AppletManagedActorRole::Ghost
        || payload.applet_id != basis.applet_id
        || payload.service_id != basis.service_id
        || payload.actor_id.route_service_id() != &basis.target_station_id
        || payload.registration_ref != basis.registration_event_ref
        || payload.applet_authority_ref != basis.authorization_ref
        || payload.external_ref.as_ref() != Some(&basis.external_ref)
    {
        return Err(BridgeError::Arkret(
            "Ghost authoring provider returned a cross-bound provision payload".to_owned(),
        ));
    }
    Ok(payload.initial_resolution.did)
}

fn validate_ghost_provision_response(
    requested_actor: &arkret::ActorId,
    response: GhostActorProvisionOutcome,
) -> Result<GhostActorProvisionOutcome> {
    if &response.ghost_actor_id != requested_actor {
        return Err(BridgeError::Arkret(format!(
            "ghost provisioning returned actor {} but requested {}",
            response.ghost_actor_id, requested_actor
        )));
    }
    Ok(response)
}

pub(crate) fn require_nonempty_ref(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(BridgeError::Arkret(format!(
            "ghost provisioning response requires {label}"
        )));
    }
    Ok(())
}

/// Map a `BridgeError` variant to a stable, plaintext-free `error_code` for the
/// `ak.applet.bridge_error` payload (§16: the code is a coarse class, not the
/// underlying message text, so it never leaks external content).
pub(crate) fn bridge_error_code(error: &BridgeError) -> &'static str {
    match error {
        BridgeError::Arkret(_) => "arkret_unavailable",
        BridgeError::Database(_) => "bridge_storage_error",
        BridgeError::Runtime(_) => "bridge_runtime_error",
        BridgeError::App(_) => "app_adapter_error",
        BridgeError::Config(_) => "bridge_misconfigured",
        BridgeError::Other(_) => "bridge_internal_error",
    }
}

pub(crate) fn bridge_error_class(error: &BridgeError) -> AppletBridgeErrorClass {
    match error {
        BridgeError::Config(_) => AppletBridgeErrorClass::Policy,
        BridgeError::App(_) => AppletBridgeErrorClass::Schema,
        BridgeError::Arkret(_)
        | BridgeError::Database(_)
        | BridgeError::Runtime(_)
        | BridgeError::Other(_) => AppletBridgeErrorClass::ExternalNetwork,
    }
}

pub(crate) fn message_mapping_channel_key(config: &runtime::Config, app_channel: &str) -> String {
    [
        bridge_protocol(config),
        bridge_tenant(config),
        normalized_external_id(app_channel),
    ]
    .join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string())
}

pub(crate) fn external_ref_for_message(
    config: &runtime::Config,
    msg: &InboundAppMessage,
) -> MessageExternalRef {
    let protocol = bridge_protocol(config);
    let tenant = bridge_tenant(config);
    let external_channel = normalized_external_id(&msg.app_channel);
    let external_event_id = normalized_external_id(&msg.app_message_id);
    let normalized_sender = normalized_external_id(&msg.app_user);

    MessageExternalRef {
        schema: EXTERNAL_REF_SCHEMA,
        protocol,
        tenant,
        external_channel,
        external_event_id,
        normalized_sender,
        source: config.bridge.bridge_id.clone(),
        app_channel: msg.app_channel.clone(),
        app_user: msg.app_user.clone(),
        app_message_id: msg.app_message_id.clone(),
    }
}

/// External provenance for an app-side delete signal. This deliberately carries
/// only IDs and coarse cause, never the message body.
pub(crate) fn external_ref_for_delete(
    config: &runtime::Config,
    delete: &InboundAppDelete,
) -> DeleteExternalRef {
    let protocol = bridge_protocol(config);
    let tenant = bridge_tenant(config);
    let external_channel = normalized_external_id(&delete.app_channel);
    let external_target_event_id = normalized_external_id(&delete.app_message_id);
    let normalized_actor = normalized_external_id(&delete.app_user);
    let external_event_id = delete
        .source_event_id
        .as_deref()
        .map(normalized_external_id)
        .filter(|value| !value.is_empty());

    DeleteExternalRef {
        schema: EXTERNAL_REF_SCHEMA,
        protocol,
        tenant,
        external_channel,
        external_target_event_id,
        external_event_id,
        normalized_actor,
        operation: "delete",
        reason: delete.reason.as_external_ref_reason(),
        source: config.bridge.bridge_id.clone(),
        app_channel: delete.app_channel.clone(),
        app_message_id: delete.app_message_id.clone(),
    }
}

/// The external location reference identifying one app channel, in the §10.1
/// match vocabulary (`protocol` / `network_id` / `location_id`).
pub(crate) fn portal_location_ref(config: &runtime::Config, app_channel: &str) -> Value {
    json!({
        "schema": EXTERNAL_REF_SCHEMA,
        "protocol": bridge_protocol(config),
        "network_id": bridge_tenant(config),
        "location_id": normalized_external_id(app_channel),
    })
}

/// §10.1 location equivalence: protocol / network_id / location_id equality.
pub(crate) fn location_matches(candidate: Option<&Value>, location: &Value) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    ["protocol", "network_id", "location_id"]
        .iter()
        .all(|key| candidate.get(*key) == location.get(*key))
}

/// §10.1 step 2: scan the portal Realm's own commit stream for an existing
/// portal strand whose recorded external location matches. Concurrent or
/// retried creates resolve to the earliest committed create, per the §10.1
/// create-idempotency rule.
///
/// "Earliest" is the lowest `stream_position` in this Realm's single commit
/// stream: the governance Station fixed that order when it signed the commits,
/// and the scan returns them in exactly that order. Only the Realm stream is
/// scanned — Circle and Sidecar streams are independent and carry no portal
/// strand creates.
///
/// The location is matched against the strand object's signed
/// `metadata.fields.external_ref` (covered by the event digest). Strand creation
/// also records the same location in the envelope's signed top-level
/// `external_ref`.
pub(crate) async fn find_existing_portal_strand(
    edge: &runtime::ArkretEdge,
    realm_id: &str,
    location: &Value,
) -> Result<Option<String>> {
    let realm_id = RealmId::new(realm_id.to_owned())?;
    let stream_ref = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let mut after_position: Option<u64> = None;
    for _ in 0..PORTAL_STRAND_SCAN_MAX_PAGES {
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: StreamScanDirection::After(after_position),
            limit: PORTAL_STRAND_SCAN_PAGE_LIMIT,
        };
        let page = edge.client().scan_commit_stream(&request).await?;
        for item in &page.committed_events {
            let Some(event) = item.reducer_input() else {
                return Err(BridgeError::Arkret(
                    "portal strand scan encountered a withheld Event; earliest-create check is unavailable"
                        .to_owned(),
                ));
            };
            if event.kind != EventKind::StrandCreate {
                continue;
            }
            let Some(object) = event.payload.get("object") else {
                continue;
            };
            if !location_matches(object.pointer("/metadata/fields/external_ref"), location) {
                continue;
            }
            let Some(strand_id) = object.get("id").and_then(Value::as_str) else {
                continue;
            };
            return Ok(Some(strand_id.to_owned()));
        }
        let Some(last) = page.committed_events.last() else {
            break;
        };
        after_position = Some(last.commit().stream_position);
        if page.committed_events.len() < usize::from(PORTAL_STRAND_SCAN_PAGE_LIMIT) {
            break;
        }
    }
    Ok(None)
}

/// §10.1 step 3: create the portal strand by submitting `ak.strand.create` under
/// the bridge's own signable identity (the service actor), recording the
/// external location in signed envelope/strand fields, and return the new strand
/// id.
pub(crate) async fn create_portal_strand(
    edge: &runtime::ArkretEdge,
    app_channel: &str,
    alias: Option<&str>,
    realm_id: &str,
    location: &Value,
) -> Result<String> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let external_ref = location
        .as_object()
        .ok_or_else(|| BridgeError::App("portal location must be an object".into()))?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let operation_id = runtime::external_operation_key("ak.strand.create", &external_ref)?;
    if let Some(event) = edge
        .retained_publication(
            &realm,
            &arkret::ActorId::service(edge.service_actor_id().clone()),
            &operation_id,
        )
        .await?
    {
        edge.submit_event(&event).await?;
        return Ok(StrandId::from_event_id(event.event_id()).to_string());
    }
    let title = alias
        .filter(|alias| !alias.trim().is_empty())
        .unwrap_or(app_channel);
    let mut strand = Strand::new_create(
        realm.clone(),
        title,
        arkret::ActorId::service(edge.service_actor_id().clone()),
    );
    strand
        .metadata
        .get_or_insert_default()
        .fields
        .insert("external_ref".to_owned(), location.clone());
    strand.tracks.clear();
    strand.tracks.insert(
        PORTAL_STRAND_TRACK.to_owned(),
        StrandTrack::discussion_primary(),
    );
    let strand_created_at = strand.created_at;
    let payload = StrandCreatePayload { object: strand };
    // Every producer-signed member rides the intent, and the one derived
    // identity covers them all. strand_create_payload semantic validation
    // requires object.created_by == actor_id (both are the stable service identity here)
    // and object.created_at == the envelope created_at.
    let intent = edge
        .service_intent::<arkret_wire::event_spec::StrandCreate>(&realm, payload)?
        .with_created_at(strand_created_at)
        .with_external_ref(
            location
                .as_object()
                .ok_or_else(|| BridgeError::App("portal location must be an object".to_owned()))?
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
    let event = edge.author_and_sign(&realm, &operation_id, intent).await?;
    edge.submit_event(&event).await?;
    // The Strand is named by `retype(event_id)` of its own accepted create.
    Ok(StrandId::from_event_id(event.event_id()).to_string())
}

#[cfg(test)]
mod provider_tests {
    use super::*;

    #[test]
    fn provision_response_cannot_replace_requested_account() {
        let principal = DidCoreId::new("ak:did_core:web:ghost.example").unwrap();
        let expected = arkret::ActorId::account(arkret::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
        ));
        for (actor, accepted) in [
            (expected.clone(), true),
            (
                arkret::ActorId::account(arkret::AccountId::new(
                    principal.clone(),
                    DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
                )),
                false,
            ),
            (arkret::ActorId::service(principal), false),
        ] {
            // Every durable provisioning ref is the accepted Event id
            // (`applet-ghost-operations.schema.json#/$defs/event_ref`).
            let event_ref = "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let response: GhostActorProvisionOutcome = serde_json::from_value(serde_json::json!({
                "ghost_actor_id": actor,
                "managed_actor_provision_ref": event_ref,
                "principal_control_realm_id": "ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "profile_event_ref": event_ref,
                "accountability_grant_ref": event_ref,
                "authorization_ref": "ak:grant:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            })).unwrap();
            assert_eq!(
                validate_ghost_provision_response(&expected, response).is_ok(),
                accepted
            );
        }
    }

    struct RejectingProvider;

    #[async_trait::async_trait]
    impl GhostProvisionRequestProvider for RejectingProvider {
        async fn author_request(
            &self,
            _request: &GhostProvisionAuthoringRequest,
        ) -> Result<GhostActorProvisionRequestBody> {
            Err(BridgeError::Config("fixture provider invoked".to_owned()))
        }
    }

    #[test]
    fn missing_authoring_provider_fails_closed() {
        assert!(require_ghost_provision_provider(None).is_err());
    }

    #[tokio::test]
    async fn installed_authoring_provider_is_the_only_request_source() {
        let provider: Arc<dyn GhostProvisionRequestProvider> = Arc::new(RejectingProvider);
        let selected = require_ghost_provision_provider(Some(&provider)).unwrap();
        let request = GhostProvisionAuthoringRequest {
            applet_id: AppletId::new("ak:applet:01904100-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkservice").unwrap(),
            actor_station_id: DidCoreId::new("ak:did_core:webvh:z6mkserver").unwrap(),
            realm_id: RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            )
            .unwrap(),
            external_ref: GhostExternalTuple {
                protocol: "fixture".to_owned(),
                instance_id: "tenant-1".to_owned(),
                external_id: "user-1".to_owned(),
            },
            display_name: None,
        };

        let error = selected.author_request(&request).await.unwrap_err();
        assert!(error.to_string().contains("fixture provider invoked"));
    }
}
