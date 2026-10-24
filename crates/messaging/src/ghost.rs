//! Ghost actor provisioning, external_ref provenance, and portal strand
//! acquisition helpers (applet-integration §9.1 / §10.1 / §16).

use std::sync::{Arc, OnceLock};

use arkret::{AppletId, Did, DidCoreId, RealmId};
use arkret_bridge_runtime::{BridgeError, PreparedGhost, Result};
use arkret_models_integration::{AppletBridgeErrorClass, GhostExternalTuple};
use serde::Serialize;
use serde_json::{Value, json};

use crate::store::MessageStore;
use crate::types::{InboundAppDelete, InboundAppMessage};
use crate::{EXTERNAL_REF_SCHEMA, MESSAGE_MAPPING_KEY_SEPARATOR, runtime};

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

/// The Realm and Applet are both part of the durable external identity key.
fn ghost_provision_idempotency_key(
    applet_id: &str,
    realm_id: &str,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let material = serde_json::to_vec(&[applet_id, realm_id, protocol, tenant, external_user_id])
        .expect("a string array is serializable");
    format!("ghost-provision-{}", hex::encode(Sha256::digest(material)))
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

/// Immutable accepted identity; business grants are acquired independently.
pub(crate) struct ProvisionedGhostActor {
    pub(crate) did: Did,
    pub(crate) actor_id: arkret::ActorId,
    pub(crate) creation_ref: arkret::CommittedEventRef,
}

/// Local authoring input. The account's identity belongs to its Realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GhostProvisionAuthoringRequest {
    pub applet_id: AppletId,
    pub service_id: DidCoreId,
    pub realm_id: RealmId,
    pub external_ref: GhostExternalTuple,
    pub display_name: Option<String>,
}

/// The provider owns independent native DID custody and exact creation replay.
#[async_trait::async_trait]
pub trait GhostProvisionRequestProvider: Send + Sync {
    async fn author_request(
        &self,
        request: &GhostProvisionAuthoringRequest,
    ) -> Result<PreparedGhost>;
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
    edge: &Arc<runtime::ArkretEdge>,
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
        realm_id: RealmId::new(realm_id.to_owned())?,
        external_ref,
        display_name: display_name.map(ToOwned::to_owned),
    };
    let idempotency_key = ghost_provision_idempotency_key(
        &config.arkret.applet_id,
        realm_id,
        &authoring_request.external_ref.protocol,
        &authoring_request.external_ref.instance_id,
        &authoring_request.external_ref.external_id,
    );
    let request_json = match store
        .clone()
        .prepared_ghost_provision_async(idempotency_key.clone())
        .await?
    {
        Some(request_json) => request_json,
        None => {
            let request = provider.author_request(&authoring_request).await?;
            let _ = validate_authored_ghost_request(&authoring_request, &request, edge).await?;
            let request_json = serde_json::to_string(&request).map_err(|error| {
                BridgeError::App(format!("Ghost provision encode failed: {error}"))
            })?;
            store
                .prepare_ghost_provision_async(idempotency_key.clone(), request_json)
                .await?
        }
    };
    let request: PreparedGhost = serde_json::from_str(&request_json).map_err(|error| {
        BridgeError::Database(format!("stored Ghost creation invalid: {error}"))
    })?;
    let did = validate_authored_ghost_request(&authoring_request, &request, edge).await?;
    let (actor_id, creation_ref) = match &request {
        PreparedGhost::Reuse { existing, .. } => (
            existing.ghost_actor_id.clone(),
            existing.creation_ref.clone(),
        ),
        PreparedGhost::Create(prepared) => {
            let payload: arkret::RealmActorCreatePayload =
                serde_json::from_value(serde_json::to_value(&prepared.create_event.payload)?)?;
            let outcome = edge.submit_managed_creation(prepared).await?;
            let arkret::AuthoritySubmitResponseBody::Accepted { commit, .. } = outcome else {
                return Err(BridgeError::Arkret(
                    "Ghost creation has not been accepted".into(),
                ));
            };
            (
                payload.actor_id,
                arkret::CommittedEventRef {
                    event_id: prepared.create_event.event_id.clone(),
                    commit_id: commit.commit_id,
                    stream_ref: commit.stream_ref,
                    stream_position: commit.stream_position,
                },
            )
        }
    };
    Ok(ProvisionedGhostActor {
        did,
        actor_id,
        creation_ref,
    })
}

async fn validate_authored_ghost_request(
    expected: &GhostProvisionAuthoringRequest,
    prepared: &PreparedGhost,
    edge: &Arc<runtime::ArkretEdge>,
) -> Result<Did> {
    let request = match prepared {
        PreparedGhost::Create(value) => &value.authoring_request,
        PreparedGhost::Reuse {
            authoring_request, ..
        } => authoring_request,
    };
    request.validate_bindings()?;
    let basis = request
        .basis
        .ghost()
        .ok_or_else(|| BridgeError::Arkret("Ghost authoring requires a Ghost basis".into()))?;
    if basis.applet_id != expected.applet_id
        || basis.service_id != expected.service_id
        || basis.effective_scope
            != (arkret::ScopeRef::Realm {
                realm_id: expected.realm_id.clone(),
            })
        || basis.external_ref != expected.external_ref
    {
        return Err(BridgeError::Arkret(
            "Ghost authoring coordinates differ".into(),
        ));
    }
    match prepared {
        PreparedGhost::Reuse { existing, .. } => {
            runtime::managed_actor_authoring::ManagedActorAuthoringService::new(edge.clone())?
                .reused_ghost_did(request, existing)
                .await
        }
        PreparedGhost::Create(value) => {
            let payload: arkret::RealmActorCreatePayload =
                serde_json::from_value(serde_json::to_value(&value.create_event.payload)?)?;
            payload.validate()?;
            let external = payload.external_ref.as_ref().ok_or_else(|| {
                BridgeError::Arkret("Ghost creation omits its external identity".into())
            })?;
            if value.create_event.kind != arkret_wire::event_kind_str::REALM_ACTOR_CREATE
                || payload.actor_role != arkret::RealmActorCreatePayloadActorRole::Ghost
                || payload.applet_id != basis.applet_id
                || payload.service_id != basis.service_id
                || payload.creation_scope != basis.effective_scope
                || payload.actor_id.as_realm_actor_id().map(|id| &id.realm_id)
                    != Some(&expected.realm_id)
                || payload.registration_ref != basis.registration_event_ref
                || payload.creation_authorization_ref != basis.authorization_ref
                || external.protocol != basis.external_ref.protocol
                || external.instance_id != basis.external_ref.instance_id
                || external.external_id != basis.external_ref.external_id
            {
                return Err(BridgeError::Arkret(
                    "Ghost creation is bound to different identity or permission".into(),
                ));
            }
            edge.validate_prepared_creation(value)?;
            Ok(payload.initial_resolution.did)
        }
    }
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

#[async_trait::async_trait]
impl GhostProvisionRequestProvider
    for runtime::managed_actor_authoring::ManagedActorAuthoringService
{
    async fn author_request(
        &self,
        request: &GhostProvisionAuthoringRequest,
    ) -> Result<PreparedGhost> {
        self.prepare_ghost(
            &request.applet_id,
            &request.realm_id,
            &request.external_ref,
            request.display_name.clone(),
        )
        .await
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;

    #[test]
    fn provision_key_separates_realms_applets_and_delimiters() {
        let key = ghost_provision_idempotency_key("applet", "realm", "p", "t", "u");
        for args in [
            ["other", "realm", "p", "t", "u"],
            ["applet", "other", "p", "t", "u"],
            ["applet", "realm", "p\u{1f}t", "", "u"],
        ] {
            assert_ne!(
                key,
                ghost_provision_idempotency_key(args[0], args[1], args[2], args[3], args[4])
            );
        }
        assert_ne!(
            ghost_provision_idempotency_key("a", "r", "p\u{1f}t", "x", "u"),
            ghost_provision_idempotency_key("a", "r", "p", "t\u{1f}x", "u")
        );
    }

    struct RejectingProvider;

    #[async_trait::async_trait]
    impl GhostProvisionRequestProvider for RejectingProvider {
        async fn author_request(
            &self,
            _request: &GhostProvisionAuthoringRequest,
        ) -> Result<PreparedGhost> {
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
