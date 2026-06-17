//! Ghost actor provisioning, external_ref provenance, and portal strand
//! acquisition helpers (applet-integration §9.1 / §10.1 / §16).

use cokret::http_client::ClientRequestOptions;
use cokret::{
    AppletId, Did, GhostActorProvisionOutcome, GhostActorProvisionRequestBody, ObjectCreatePayload,
    RealmId, StrandCreateObject, StrandId, StrandTrackConfig,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

use crate::types::InboundAppMessage;
use crate::{
    EXTERNAL_REF_SCHEMA, MESSAGE_MAPPING_KEY_SEPARATOR, PORTAL_STRAND_SCAN_MAX_PAGES,
    PORTAL_STRAND_SCAN_PAGE_LIMIT, PORTAL_STRAND_TRACK, runtime,
};

pub(crate) fn normalized_external_id(value: &str) -> String {
    value.trim().to_owned()
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
    let material =
        [protocol, tenant, external_user_id].join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string());
    let encoded = cokret::base64url_encode(material.as_bytes());
    let did = format!(
        "{}:ghost:u{encoded}",
        config.cokret.service_did.trim_end_matches(':')
    );
    Did::new(did.clone())?;
    Ok(did)
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

fn external_ref_for_user(
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> Value {
    json!({
        "protocol": protocol,
        "tenant": tenant,
        "external_user_id": external_user_id,
        "source": config.bridge.bridge_id.clone(),
    })
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
        external_ref_for_user(config, protocol, tenant, external_user_id),
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

pub(crate) fn message_mapping_channel_key(config: &runtime::Config, app_channel: &str) -> String {
    [
        bridge_protocol(config),
        bridge_tenant(config),
        normalized_external_id(app_channel),
    ]
    .join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string())
}

pub(crate) fn external_ref_for_message(config: &runtime::Config, msg: &InboundAppMessage) -> Value {
    let protocol = bridge_protocol(config);
    let tenant = bridge_tenant(config);
    let external_channel = normalized_external_id(&msg.app_channel);
    let external_event_id = normalized_external_id(&msg.app_message_id);
    let normalized_sender = normalized_external_id(&msg.app_user);

    json!({
        "schema": EXTERNAL_REF_SCHEMA,
        "protocol": protocol,
        "tenant": tenant,
        "external_channel": external_channel,
        "external_event_id": external_event_id,
        "normalized_sender": normalized_sender,
        "source": config.bridge.bridge_id.clone(),
        "app_channel": msg.app_channel.clone(),
        "app_user": msg.app_user.clone(),
        "app_message_id": msg.app_message_id.clone(),
    })
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
/// `metadata.fields.external_ref` (covered by the event digest). The spec's
/// envelope-top-level signed `external_ref` is not yet representable in the SDK
/// `Event` model, so strand creation mirrors the location into the signed strand
/// metadata (see [`create_portal_strand`]).
pub(crate) async fn find_existing_portal_strand(
    edge: &runtime::CokretEdge,
    realm_id: &str,
    location: &Value,
) -> Result<Option<String>> {
    let mut cursor: Option<String> = None;
    // (hlc, event_id, strand_id) — keep the earliest in effective order.
    let mut earliest: Option<(String, String, String)> = None;
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
            let key = (event.hlc.to_string(), event.event_id.to_string());
            if earliest.as_ref().is_none_or(|(hlc, event_id, _)| {
                (key.0.as_str(), key.1.as_str()) < (hlc.as_str(), event_id.as_str())
            }) {
                earliest = Some((key.0, key.1, strand_id.to_owned()));
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
/// external location in the signed strand metadata, and return the new strand id.
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
    let mut event = edge.mint_event("ck.strand.create", &realm, payload)?;
    // strand_create_payload semantic validation requires object.created_by ==
    // actor_id (both are the service DID here) and object.created_at == the
    // envelope created_at.
    event.created_at = strand_created_at;
    // §10.1 asks for a signed envelope top-level external_ref recording the
    // location; the SDK Event model cannot carry that field yet, so the signed
    // copy lives in the strand metadata above and unsigned only carries a hint.
    event
        .unsigned
        .insert("external_ref".to_owned(), location.clone());
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
