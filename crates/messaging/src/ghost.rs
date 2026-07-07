//! Ghost actor provisioning, external_ref provenance, and portal strand
//! acquisition helpers (applet-integration §9.1 / §10.1 / §16).

use cokret::http_client::ClientRequestOptions;
use cokret::{
    AppletBridgeErrorClass, AppletId, Did, EventId, GhostActorProvisionOutcome,
    GhostActorProvisionRequestBody, Hlc, ObjectCreatePayload, RealmId, StrandCreateObject,
    StrandId, StrandTrackConfig,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde::Serialize;
use serde_json::{Value, json};

use crate::types::{InboundAppDelete, InboundAppMessage};
use crate::{
    EXTERNAL_REF_SCHEMA, MESSAGE_MAPPING_KEY_SEPARATOR, PORTAL_STRAND_SCAN_MAX_PAGES,
    PORTAL_STRAND_SCAN_PAGE_LIMIT, PORTAL_STRAND_TRACK, runtime,
};

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
        .unwrap_or_else(|| normalized_external_id(&config.cokret.service_did))
}

fn requested_ghost_actor_id_for_user(
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> Result<String> {
    if protocol.trim().is_empty() {
        return Err(BridgeError::App("bridge protocol must not be empty".into()));
    }
    if tenant.trim().is_empty() {
        return Err(BridgeError::App("bridge tenant must not be empty".into()));
    }
    if external_user_id.trim().is_empty() {
        return Err(BridgeError::App(
            "inbound app_user is required for ghost actor mapping".into(),
        ));
    }
    // The default ghost derivation appends a `:ghost:u<...>` suffix to the
    // service DID (applet-integration §3.4). Only `did:webvh` is accepted per
    // the workspace-wide webvh-only rule; for other methods (e.g. `did:key`)
    // the bare suffix would not even be a valid actor DID. Assert the method
    // before deriving so a misconfigured service DID fails closed here rather
    // than producing a malformed ghost id.
    let service_did = Did::new(config.cokret.service_did.clone())?;
    assert_ghost_suffix_method(&service_did)?;
    let material =
        [protocol, tenant, external_user_id].join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string());
    let encoded = cokret::base64url_encode(material.as_bytes());
    let did = format!(
        "{}:ghost:u{encoded}",
        service_did.as_str().trim_end_matches(':')
    );
    Did::new(did.clone())?;
    Ok(did)
}

/// Assert that `service_did`'s method supports the `:ghost:*` suffix derivation
/// used for default applet namespaces and ghost actor ids. Only `did:webvh` is
/// valid (workspace-wide webvh-only rule; the applet-integration §3.4 examples
/// are webvh as well).
pub(crate) fn assert_ghost_suffix_method(service_did: &Did) -> Result<()> {
    match service_did.method() {
        "webvh" => Ok(()),
        other => Err(BridgeError::Config(format!(
            "service DID method `{other}` is not allowed; \
             a bridge service DID must be did:webvh"
        ))),
    }
}

/// The spec-registered ghost provision binding: `ck.self.applet.ghost.command.provision`
/// = `POST /_cokret/self/applets/{applet_id}/ghosts/provision`
/// (applet-integration §9.1, `operation-registry.json`, openapi).
fn ghost_actor_provision_path(applet_id: &str) -> Result<String> {
    if applet_id.trim().is_empty() || applet_id.contains('/') {
        return Err(BridgeError::Config(
            "cokret.applet_id must be a non-empty path-safe ck:applet id".into(),
        ));
    }
    Ok(format!(
        "/_cokret/self/applets/{applet_id}/ghosts/provision"
    ))
}

/// Deterministic `Idempotency-Key` for ghost provisioning (required header per
/// the openapi binding; §9.1 keys server-side idempotency on
/// `(applet_id, protocol, tenant, external_user_id)`, so retries of the same
/// external user reuse the same key). Hashed to satisfy the 128-char bound.
fn ghost_provision_idempotency_key(
    applet_id: &str,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let material = [applet_id, protocol, tenant, external_user_id]
        .join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string());
    format!(
        "ghost-provision-{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

#[derive(Clone, Debug, Serialize)]
struct UserExternalRef {
    protocol: String,
    tenant: String,
    external_user_id: String,
    source: String,
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

fn external_ref_for_user(
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> UserExternalRef {
    UserExternalRef {
        protocol: protocol.to_owned(),
        tenant: tenant.to_owned(),
        external_user_id: external_user_id.to_owned(),
        source: config.bridge.bridge_id.clone(),
    }
}

fn external_ref_value<T>(external_ref: T) -> Result<Value>
where
    T: Serialize,
{
    serde_json::to_value(external_ref)
        .map_err(|error| BridgeError::App(format!("external_ref serialization failed: {error}")))
}

pub(crate) async fn provision_ghost_actor(
    edge: &runtime::CokretEdge,
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
    display_name: Option<&str>,
    realm_id: &str,
) -> Result<GhostActorProvisionOutcome> {
    let ghost_actor_id = Did::new(requested_ghost_actor_id_for_user(
        config,
        protocol,
        tenant,
        external_user_id,
    )?)?;
    let mut request = GhostActorProvisionRequestBody::new(
        AppletId::new(config.cokret.applet_id.clone())?,
        edge.service_did().clone(),
        ghost_actor_id.clone(),
        protocol,
        tenant,
        external_user_id,
        RealmId::new(realm_id.to_owned())?,
        external_ref_value(external_ref_for_user(
            config,
            protocol,
            tenant,
            external_user_id,
        ))?,
    );
    if let Some(display_name) = display_name {
        request = request.with_display_name(display_name);
    }
    let path = ghost_actor_provision_path(&config.cokret.applet_id)?;
    let options = ClientRequestOptions::new().idempotency_key(ghost_provision_idempotency_key(
        &config.cokret.applet_id,
        protocol,
        tenant,
        external_user_id,
    ));
    let response: GhostActorProvisionOutcome = edge
        .client()
        .post_with_options(&path, &request, &options)
        .await?;
    validate_ghost_provision_response(&ghost_actor_id, response)
}

fn validate_ghost_provision_response(
    requested_actor: &Did,
    response: GhostActorProvisionOutcome,
) -> Result<GhostActorProvisionOutcome> {
    if &response.ghost_actor_id != requested_actor {
        return Err(BridgeError::Cokret(format!(
            "ghost provisioning returned actor {} but requested {}",
            response.ghost_actor_id, requested_actor
        )));
    }
    require_nonempty_ref("profile_event_ref", &response.profile_event_ref)?;
    require_nonempty_ref(
        "accountability_grant_ref",
        &response.accountability_grant_ref,
    )?;
    require_nonempty_ref("authorization_ref", &response.authorization_ref)?;
    Ok(response)
}

pub(crate) fn require_nonempty_ref(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(BridgeError::Cokret(format!(
            "ghost provisioning response requires {label}"
        )));
    }
    Ok(())
}

/// Map a `BridgeError` variant to a stable, plaintext-free `error_code` for the
/// `ck.applet.bridge_error` payload (§16: the code is a coarse class, not the
/// underlying message text, so it never leaks external content).
pub(crate) fn bridge_error_code(error: &BridgeError) -> &'static str {
    match error {
        BridgeError::Cokret(_) => "cokret_unavailable",
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
        BridgeError::Cokret(_)
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

/// §10.1 step 2: scan the portal realm's history (a projection over regular
/// event reads) for an existing portal strand whose recorded external location
/// matches. Concurrent/retried creates resolve to the earliest strand in
/// effective (HLC) order, per the §10.1 create-idempotency rule.
///
/// The location is matched against the strand object's signed
/// `metadata.fields.external_ref` (covered by the event digest). Strand creation
/// also records the same location in the envelope's signed top-level
/// `external_ref`.
pub(crate) async fn find_existing_portal_strand(
    edge: &runtime::CokretEdge,
    realm_id: &str,
    location: &Value,
) -> Result<Option<String>> {
    let mut cursor: Option<String> = None;
    // (hlc, event_id, strand_id) — keep the earliest in effective order.
    // BRG-REL-003: compare the *typed* `Hlc`/`EventId` (whose `Ord` parses the
    // HLC into (physical_ms, logical, node_id)) rather than a lexicographic
    // `to_string()` comparison, so the §10.1 "earliest effective" tie-break is
    // the authoritative HLC order regardless of the string encoding.
    let mut earliest: Option<(Hlc, EventId, String)> = None;
    for _ in 0..PORTAL_STRAND_SCAN_MAX_PAGES {
        let page = edge
            .client()
            .events_query(
                realm_id,
                cursor.as_deref(),
                None,
                None,
                Some(PORTAL_STRAND_SCAN_PAGE_LIMIT),
            )
            .await?;
        for event in &page.events {
            if event.kind.as_str() != "ck.strand.create" {
                continue;
            }
            let Some(object) = event.content.get("object") else {
                continue;
            };
            if !location_matches(object.pointer("/metadata/fields/external_ref"), location) {
                continue;
            }
            let Some(strand_id) = object.get("id").and_then(Value::as_str) else {
                continue;
            };
            if earliest
                .as_ref()
                .is_none_or(|(hlc, event_id, _)| (&event.hlc, &event.event_id) < (hlc, event_id))
            {
                earliest = Some((
                    event.hlc.clone(),
                    event.event_id.clone(),
                    strand_id.to_owned(),
                ));
            }
        }
        if page.events.is_empty() {
            break;
        }
        match page.prev_cursor {
            Some(prev) => cursor = Some(prev),
            None => break,
        }
    }
    Ok(earliest.map(|(_, _, strand_id)| strand_id))
}

/// §10.1 step 3: create the portal strand by submitting `ck.strand.create` under
/// the bridge's own signable identity (the service actor), recording the
/// external location in signed envelope/strand fields, and return the new strand
/// id.
pub(crate) async fn create_portal_strand(
    edge: &runtime::CokretEdge,
    app_channel: &str,
    alias: Option<&str>,
    realm_id: &str,
    location: &Value,
) -> Result<String> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let strand_id = StrandId::new(cokret::new_prefixed_uuid7("ck:strand:"))?;
    let title = alias
        .filter(|alias| !alias.trim().is_empty())
        .unwrap_or(app_channel);
    let strand =
        StrandCreateObject::new(strand_id.clone(), realm.clone(), edge.service_did().clone())
            .with_metadata_title(title)
            .with_metadata_field("external_ref", location.clone())
            .with_track(PORTAL_STRAND_TRACK, StrandTrackConfig::discussion_primary());
    let strand_created_at = strand.created_at;
    let payload = ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))?;
    // Build unsigned, set the signed-envelope fields, then sign once (no
    // discarded first signature). strand_create_payload semantic validation
    // requires object.created_by == actor_id (both are the service DID here) and
    // object.created_at == the envelope created_at.
    let mut event = edge.mint_event_unsigned("ck.strand.create", &realm, payload)?;
    event.created_at = strand_created_at;
    event.external_ref = Some(location.clone());
    edge.resign_event(&mut event)?;
    edge.submit_event(&event).await?;
    Ok(strand_id.to_string())
}

pub(crate) fn host_allowed(host: &str, allowed_hosts: &[&str]) -> bool {
    allowed_hosts.iter().any(|allowed| {
        host.eq_ignore_ascii_case(allowed)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", allowed.to_ascii_lowercase()))
    })
}
