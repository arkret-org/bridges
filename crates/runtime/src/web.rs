//! salvo HTTP service: health check / metrics / provisioning, plus mounting
//! the arkret applet routes (`/_arkret/edge/applet/*`) to receive event pushes
//! from the arkret server.

use std::sync::{Arc, OnceLock};

use ::metrics::{counter, describe_counter};
use arkret::identity::public_key_material_from_binding;
use arkret::signatures::generated::http_signature_contract::HttpSignatureScenario;
use arkret::signatures::http_signature::{
    HttpMessageVerificationError, SignaturePolicyError, SignatureVerificationPolicy,
    parse_signature_input, public_key_from_bytes, verify_signed_http_message,
};
use arkret::{
    AppletHandler, Did, DidCoreId, IdempotencyDirection, IdempotencyIdentity, TransactionClaim,
    TransactionIdempotencyStore, project_did_to_core_id,
};
use arkret_models_integration::{AppletTransactionOutcome, AppletTransactionRequestBody};
use arkret_wire::{DidUrl, ServiceOperationId};
use chrono::Utc;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use salvo::affix_state;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::app::BridgeContext;
use crate::arkret_edge::BridgeAppletHandler;
use crate::config::Config;
use crate::db::DbTransactionIdempotencyStore;
use crate::did_binding::{
    AcceptedDidBindings, BindingLookupError, DidAuthority, verification_method_did,
};
use crate::error::{BridgeError, Result};
use crate::run_blocking;

static PROMETHEUS_HANDLE: OnceLock<std::result::Result<PrometheusHandle, String>> = OnceLock::new();
/// Upper bound on the inbound edge `transactions` body, mirroring the webhook
/// surface's bounded read. The Applet authoring completion may contain a full
/// committed installation request, so the protocol ceiling is 16 MiB. Without
/// it the body is buffered
/// into memory in full *before* signature verification, an unauthenticated
/// memory-pressure vector on any deployment that exposes this surface.
const MAX_APPLET_TRANSACTION_BODY_BYTES: usize = 16 * 1024 * 1024;
const SOURCE_SERVICE_ID_HEADER: &str = "source-service-id";
const DESTINATION_SERVICE_ID_HEADER: &str = "destination-service-id";

/// Select the exact registered operation before its handler reads a body.
pub(crate) struct OperationSelector(pub &'static str);

#[async_trait]
impl Handler for OperationSelector {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let mut values = req.headers().get_all("arkret-operation").iter();
        let Some(first) = values.next() else {
            applet_error(
                res,
                StatusCode::BAD_REQUEST,
                "operation_selector_required",
                "canonical Arkret requests require Arkret-Operation",
            );
            ctrl.skip_rest();
            return;
        };
        let valid = first
            .to_str()
            .ok()
            .filter(|value| *value == self.0)
            .and_then(ServiceOperationId::from_wire)
            .is_some_and(|operation| {
                operation.matches_http_request(req.method().as_str(), req.uri().path())
            });
        if !valid || values.next().is_some() {
            applet_error(
                res,
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_operation_version",
                "Arkret-Operation must select the exact supported method and path exactly once",
            );
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
        if res.status_code.unwrap_or(StatusCode::OK).is_success() {
            res.headers_mut().insert(
                "arkret-operation",
                salvo::http::HeaderValue::from_static(self.0),
            );
        }
    }
}

/// Start the web service and run it blocking. `extra` is each app adapter's
/// webhook routes (optional).
pub async fn serve(
    ctx: Arc<BridgeContext>,
    extra: Option<Router>,
    internal: Option<Router>,
) -> Result<()> {
    prometheus_handle()
        .map_err(|err| BridgeError::Runtime(format!("metrics recorder init failed: {err}")))?;
    counter!(
        "arkret_bridge_runtime_starts_total",
        "bridge_id" => ctx.config.bridge.bridge_id.clone()
    )
    .increment(1);

    // Durable idempotency / dedup records (applet-integration §7.3 / §13):
    // both stores persist in the bridge database so restarts do not turn
    // server retries into duplicate deliveries.
    let idempotency: Arc<
        dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>,
    > = Arc::new(DbTransactionIdempotencyStore::new(ctx.db.clone())?);
    // The inbound path carries no DID resolver at all: `DidAuthority` owns the
    // accepted-binding store and nothing else. The trusted server's
    // HTTP-signature keys are accepted from configuration at startup, so
    // authenticating an inbound push costs zero network calls even on the very
    // first request, and an unconfigured key fails closed rather than
    // triggering a lookup.
    let did_authority = Arc::new(DidAuthority::new(ctx.config.arkret.trust_domain.clone())?);
    seed_source_service_bindings(&did_authority, &ctx.config)?;
    let handler = Arc::new(BridgeAppletHandler::new(
        &ctx.edge,
        ctx.resolver(),
        did_authority.clone(),
    )?);
    let applet = applet_router(AppletWebState {
        edge: ctx.edge.clone(),
        handler,
        config: ctx.config.clone(),
        idempotency,
        did_authority: did_authority.clone(),
    });

    // Internal plane: the trusted applet protocol surface
    // (`/_arkret/edge/applet/*`), the ops surface (`/health` + `/metrics`) and
    // the operator command surface (`/admin/*`) share one loopback-by-default
    // acceptor. Keeping these off the public webhook bind means "no reverse
    // proxy configured" still isolates the trusted and ops planes from the
    // public network (BRG-06-004); the operator invalidation endpoint relies on
    // exactly that same network-isolation posture.
    let mut admin_router = Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("metrics").get(metrics_endpoint))
        .push(admin_did_bindings_router(AdminWebState { did_authority }))
        .push(applet);
    #[cfg(feature = "managed-authoring")]
    {
        admin_router = admin_router.push(managed_applet_router(ctx.edge.clone())?);
    }
    #[cfg(not(feature = "managed-authoring"))]
    {
        admin_router = admin_router.push(service_description_router(&ctx.edge)?);
    }
    if let Some(internal) = internal {
        admin_router = admin_router.push(internal);
    }

    let admin_addr = ctx.config.bridge.admin_addr();
    tracing::info!(addr = %admin_addr, "admin/edge plane listening (applet + health/metrics)");
    let admin_acceptor = TcpListener::new(admin_addr).bind().await;
    let admin_server = Server::new(admin_acceptor).serve(admin_router);

    // Public plane: each adapter's webhook routes (`/webhooks/*`, plus Teams'
    // Bot Framework `/api/messages`). This is the only plane that must face the
    // external platform callbacks, so it binds `0.0.0.0` by default.
    if let Some(app_routes) = extra {
        // Default-on per-source-IP rate limiting (BRG-SOTA-01 posture: the
        // "isolated by default" dual-listener design extends to "rate-limited
        // by default"). The quota is deliberately generous so platform
        // redelivery storms are not clipped; operators can widen/disable it
        // via `bridge.webhook_rate_limit`.
        let rate_limit = &ctx.config.bridge.webhook_rate_limit;
        let webhook_router = if rate_limit.enabled {
            use salvo::rate_limiter::{
                BasicQuota, FixedGuard, MokaStore, RateLimiter, RemoteIpIssuer,
            };
            tracing::info!(
                max_requests = rate_limit.max_requests,
                window_secs = rate_limit.window_secs,
                "webhook plane per-IP rate limit enabled"
            );
            let limiter = RateLimiter::new(
                FixedGuard::default(),
                MokaStore::default(),
                RemoteIpIssuer,
                BasicQuota::set_seconds(rate_limit.max_requests, rate_limit.window_secs as i64),
            );
            Router::new().hoop(limiter).push(app_routes)
        } else {
            Router::new().push(app_routes)
        };
        let webhook_addr = ctx.config.bridge.webhook_addr();
        tracing::info!(addr = %webhook_addr, "webhook plane listening (public platform callbacks)");
        let webhook_acceptor = TcpListener::new(webhook_addr).bind().await;
        let webhook_server = Server::new(webhook_acceptor).serve(webhook_router);
        tokio::join!(admin_server, webhook_server);
    } else {
        // Gateway / long-poll bridges expose no public webhook plane; only the
        // internal admin/edge acceptor runs.
        admin_server.await;
    }

    Err(BridgeError::Runtime(
        "web service exited unexpectedly".into(),
    ))
}

#[handler]
async fn health(res: &mut Response) {
    counter!("arkret_bridge_health_requests_total").increment(1);
    res.render(Json(serde_json::json!({ "status": "ok" })));
}

#[handler]
async fn metrics_endpoint(res: &mut Response) {
    counter!("arkret_bridge_metrics_scrapes_total").increment(1);
    match prometheus_handle() {
        Ok(handle) => res.render(Text::Plain(handle.render())),
        Err(err) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain(format!(
                "metrics recorder unavailable: {err}\n"
            )));
        }
    }
}

fn prometheus_handle() -> std::result::Result<&'static PrometheusHandle, String> {
    match PROMETHEUS_HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .map_err(|err| err.to_string())?;
        describe_counter!(
            "arkret_bridge_runtime_starts_total",
            "Bridge runtime start count, labelled by bridge_id."
        );
        describe_counter!(
            "arkret_bridge_health_requests_total",
            "Bridge /health request count."
        );
        describe_counter!(
            "arkret_bridge_metrics_scrapes_total",
            "Bridge /metrics scrape count."
        );
        describe_counter!(
            "arkret_bridge_applet_transactions_total",
            "Applet transaction request count, labelled by result."
        );
        describe_counter!(
            "arkret_bridge_did_binding_invalidations_total",
            "Operator DID-binding invalidation request count, labelled by result."
        );
        Ok(handle)
    }) {
        Ok(handle) => Ok(handle),
        Err(err) => Err(err.clone()),
    }
}

fn record_applet_transaction(result: &'static str) {
    counter!("arkret_bridge_applet_transactions_total", "result" => result).increment(1);
}

fn record_did_binding_invalidation(result: &'static str) {
    counter!("arkret_bridge_did_binding_invalidations_total", "result" => result).increment(1);
}

/// Operator command surface state for the admin plane (`/admin/*`).
#[derive(Clone)]
struct AdminWebState {
    did_authority: Arc<DidAuthority>,
}

/// Body of `POST /admin/did-bindings/invalidate`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidateDidBindingsRequest {
    /// The DID whose accepted bindings must be dropped.
    did: String,
    /// Optional guard: when present it must equal this bridge's configured
    /// trust domain. The sweep itself is always scoped to that domain, so a
    /// mismatch is a rejected request rather than a silent cross-domain no-op.
    #[serde(default)]
    trust_domain: Option<String>,
}

/// The operator command surface for `identity/did-usage-and-verification.md`
/// §5.6: rotation, deactivation, witness fork and explicit revocation MUST
/// invalidate the affected bindings. A bridge holds no resolver and receives no
/// rotation notifications, so the runtime trigger for that obligation is the
/// operator invoking this endpoint (see the README section on DID binding invalidation).
///
/// Protection model: identical to `/health` and `/metrics` — the admin plane
/// binds loopback by default (BRG-06-004) and carries no request-level
/// authentication of its own. An operator who widens `admin_bind` is expected
/// to gate the whole plane at the network / reverse-proxy layer.
fn admin_did_bindings_router(state: AdminWebState) -> Router {
    Router::with_path("admin/did-bindings/invalidate")
        .hoop(affix_state::inject(state))
        .post(admin_invalidate_did_bindings)
}

#[handler]
async fn admin_invalidate_did_bindings(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<AdminWebState>() else {
        record_did_binding_invalidation("internal_error");
        internal_error(res, "admin web state missing");
        return;
    };
    let body: InvalidateDidBindingsRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(err) => {
            record_did_binding_invalidation("bad_request");
            bad_request(res, format!("invalid invalidation request body: {err}"));
            return;
        }
    };
    let did = match Did::new(body.did) {
        Ok(did) => did,
        Err(err) => {
            record_did_binding_invalidation("bad_request");
            bad_request(res, format!("`did` is not a valid DID: {err}"));
            return;
        }
    };
    let trust_domain = state.did_authority.trust_domain();
    if let Some(requested) = body.trust_domain.as_deref()
        && requested != trust_domain.as_str()
    {
        record_did_binding_invalidation("trust_domain_mismatch");
        // The admin surface is not part of the applet universal failure
        // surface, so this code is not bound to the closed applet registry.
        applet_error(
            res,
            StatusCode::CONFLICT,
            "trust_domain_mismatch",
            format!(
                "trust_domain `{requested}` does not match this bridge's \
                 trust domain `{trust_domain}`; refusing to sweep"
            ),
        );
        return;
    }
    // §5.6 `for_did` coarse sweep, scoped to this bridge's trust domain. Zero
    // dropped acceptances is still a success: the sweep is idempotent, and an
    // operator retrying a revocation must not read the retry as a failure.
    let invalidated = state.did_authority.invalidate_did(&did);
    record_did_binding_invalidation("invalidated");
    tracing::info!(
        did = %did,
        trust_domain = %trust_domain,
        invalidated,
        "operator invalidated accepted DID bindings"
    );
    res.render(Json(json!({
        "ok": true,
        "did": did.as_str(),
        "trust_domain": trust_domain.as_str(),
        "invalidated_bindings": invalidated,
    })));
}

#[derive(Clone)]
struct AppletWebState {
    edge: Arc<crate::ArkretEdge>,
    handler: Arc<BridgeAppletHandler>,
    config: Arc<Config>,
    idempotency:
        Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    /// Inbound DID authority adapter. Handlers may reach its §4 entry points;
    /// nothing can reach the resolver it wraps.
    did_authority: Arc<DidAuthority>,
}

async fn claim_transaction(
    store: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    replay: IdempotencyIdentity,
    hash: String,
    delivery_authentication_record_digest: String,
) -> Result<TransactionClaim<AppletTransactionOutcome>> {
    run_blocking(move || store.claim(&replay, &hash, &delivery_authentication_record_digest)).await
}

/// Authenticate every Event before creating the durable idempotency claim.
///
/// The claim is the first transaction-processing side effect. Keeping proof
/// verification ahead of it means an unauthenticated request cannot create a
/// `pending` row and correctness never depends on a compensating release.
async fn authenticate_and_claim_transaction(
    body: AppletTransactionRequestBody,
    store: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    replay: IdempotencyIdentity,
    hash: String,
    delivery_authentication_record_digest: String,
) -> Result<std::result::Result<TransactionClaim<AppletTransactionOutcome>, String>> {
    let authentication = run_blocking(move || Ok(verify_transaction_events(&body))).await?;
    match authentication {
        Ok(()) => claim_transaction(store, replay, hash, delivery_authentication_record_digest)
            .await
            .map(Ok),
        Err(err) => Ok(Err(err)),
    }
}

async fn release_transaction_claim(
    store: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    replay: IdempotencyIdentity,
    hash: String,
    delivery_authentication_record_digest: String,
) -> Result<()> {
    run_blocking(move || store.release(&replay, &hash, &delivery_authentication_record_digest))
        .await
}

async fn record_transaction_outcome(
    store: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    replay: IdempotencyIdentity,
    hash: String,
    delivery_authentication_record_digest: String,
    response: AppletTransactionOutcome,
) -> Result<()> {
    run_blocking(move || {
        store.record(
            &replay,
            &hash,
            &delivery_authentication_record_digest,
            &response,
        )
    })
    .await
}

struct HttpSignatureReject {
    code: &'static str,
    message: String,
}

/// Embed the production completion receiver without the bridge process/SQL
/// bootstrap. Hosts supply the SDK claim store; the edge's durable journal
/// owns accepted originals and full delivery receipts across cold restarts.
pub fn applet_completion_router(
    edge: Arc<crate::ArkretEdge>,
    idempotency: Arc<
        dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>,
    >,
) -> Result<Router> {
    let config = edge.config().clone();
    let did_authority = Arc::new(DidAuthority::new(config.arkret.trust_domain.clone())?);
    let handler = Arc::new(BridgeAppletHandler::new(
        &edge,
        None,
        did_authority.clone(),
    )?);
    Ok(Router::with_path("_arkret/edge/applet/transactions")
        .hoop(affix_state::inject(AppletWebState {
            edge,
            handler,
            config,
            idempotency,
            did_authority,
        }))
        .hoop(OperationSelector(
            ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
        ))
        .post(applet_transactions))
}

fn applet_router(state: AppletWebState) -> Router {
    applet_routes().hoop(affix_state::inject(state))
}

fn applet_routes() -> Router {
    let router = Router::with_path("_arkret/edge/applet")
        .push(
            Router::with_path("ping")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_READ_PING_V1,
                ))
                .get(applet_ping),
        )
        .push(
            Router::with_path("describe")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_READ_DESCRIBE_V1,
                ))
                .get(applet_describe),
        )
        .push(
            Router::with_path("transactions")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
                ))
                .post(applet_transactions),
        )
        .push(
            Router::with_path("actors/{actor_id}")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE_V1,
                ))
                .get(applet_actor),
        )
        .push(
            Router::with_path("realms/{realm_id_or_alias}")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE_V1,
                ))
                .get(applet_realm),
        )
        .push(
            Router::with_path("protocols/{protocol}")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA_V1,
                ))
                .get(applet_protocol),
        )
        // The applet edge surface declares eight operations; the third_party
        // user/location lookups are not backed by a server-side discovery index
        // here. Per applet-integration §15 an unimplemented surface MUST return a
        // structured `unsupported_feature` rather than fall through to a bare 404.
        .push(
            Router::with_path("third_party/users")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST_V1,
                ))
                .get(applet_third_party_unsupported),
        )
        .push(
            Router::with_path("third_party/locations")
                .hoop(OperationSelector(
                    ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST_V1,
                ))
                .get(applet_third_party_unsupported),
        );
    router
}

#[cfg(feature = "managed-authoring")]
#[derive(Clone)]
struct ConfigurationWebState {
    service: Arc<crate::applet_configuration::AppletConfigurationService>,
    config: Arc<Config>,
    did_authority: Arc<DidAuthority>,
}

fn service_description_router(edge: &crate::ArkretEdge) -> Result<Router> {
    let identity = crate::service_identity::router(edge.config())?;
    let authority = Arc::new(DidAuthority::new(
        edge.config().arkret.trust_domain.clone(),
    )?);
    let mut description = BridgeAppletHandler::new(edge, None, authority)?.describe()?;
    description
        .supported_operation_bundles
        .push("ak.operation_bundle.applet_service.service_resolution.v1".to_owned());
    description.supported_operation_bundles.sort();
    description.validate()?;
    Ok(Router::new().push(identity).push(
        Router::with_path("_arkret/describe")
            .hoop(OperationSelector(
                ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            ))
            .hoop(affix_state::inject(description))
            .get(service_describe),
    ))
}

#[handler]
async fn service_describe(depot: &mut Depot, res: &mut Response) {
    match depot.get_typed::<arkret_models_discovery::ServiceDescribe>() {
        Ok(description) => res.render(Json(description.clone())),
        Err(_) => internal_error(res, "Applet service description is unavailable"),
    }
}

/// The production managed Applet surface shared by standalone and embedded
/// hosts. Reverse proxies must expose its native DID publication paths too.
#[cfg(feature = "managed-authoring")]
pub fn managed_applet_router(edge: Arc<crate::ArkretEdge>) -> Result<Router> {
    let description = service_description_router(&edge)?;
    let config = edge.config().clone();
    let did_authority = Arc::new(DidAuthority::new(config.arkret.trust_domain.clone())?);
    seed_source_service_bindings(&did_authority, &config)?;
    let author =
        Arc::new(crate::managed_actor_authoring::ManagedActorAuthoringService::new(edge.clone())?);
    let service = Arc::new(crate::applet_configuration::AppletConfigurationService::new(edge)?);
    Ok(Router::new().push(description).push(author.router()).push(
        Router::with_path("_arkret/edge/applet/configuration")
            .hoop(OperationSelector(
                ServiceOperationId::EDGE_APPLET_CONFIGURATION_COMMAND_EXECUTE_V1,
            ))
            .hoop(affix_state::inject(ConfigurationWebState {
                service,
                config,
                did_authority,
            }))
            .post(applet_configuration),
    ))
}

#[cfg(feature = "managed-authoring")]
#[handler]
async fn applet_configuration(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<ConfigurationWebState>().cloned() else {
        internal_error(res, "managed Applet state is unavailable");
        return;
    };
    let headers = collect_headers(req);
    if header_value_from(&headers, "idempotency-key").is_none_or(|key| key.trim().is_empty()) {
        bad_request(res, "Idempotency-Key header is required");
        return;
    }
    let bytes = match req.payload().await {
        Ok(bytes) if bytes.len() <= 262_144 => bytes.to_vec(),
        Ok(_) => {
            applet_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "configuration exceeds its registered body limit",
            );
            return;
        }
        Err(error) => {
            bad_request(res, error.to_string());
            return;
        }
    };
    let body: arkret_models_integration::AppletConfigurationExecutionRequest =
        match serde_json::from_slice(&bytes) {
            Ok(body) => body,
            Err(error) => {
                bad_request(res, error.to_string());
                return;
            }
        };
    let service = &state.service;
    let route = match service.verify_request(&body).await {
        Ok(route) => route,
        Err(error) => {
            unauthorized(res, error.to_string());
            return;
        }
    };
    if let Err(error) = verify_http_applet_request_with_scenario(
        req,
        &headers,
        &bytes,
        &state.config,
        state.did_authority.bindings(),
        Some(&route),
        HttpSignatureScenario::ServiceToServiceV1,
        &["content-digest", "idempotency-key"],
    ) {
        unauthorized_code(res, error.code, error.message);
        return;
    }
    match service.execute(&body).await {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => bad_request(res, error.to_string()),
    }
}

#[handler]
async fn applet_ping(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) =
        verify_http_applet_get_request(req, &state.config, state.did_authority.bindings())
    {
        unauthorized_code(res, err.code, err.message);
        return;
    }
    match state.handler.ping() {
        Ok(body) => res.render(Json(body)),
        Err(err) => internal_error(res, err.to_string()),
    }
}

#[handler]
async fn applet_describe(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) =
        verify_http_applet_get_request(req, &state.config, state.did_authority.bindings())
    {
        unauthorized_code(res, err.code, err.message);
        return;
    }
    match state.handler.describe() {
        Ok(body) => res.render(Json(body)),
        Err(err) => internal_error(res, err.to_string()),
    }
}

#[handler]
async fn applet_transactions(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        record_applet_transaction("missing_state");
        return;
    };
    let headers = collect_headers(req);
    let body_bytes = match req.payload().await {
        Ok(bytes) if bytes.len() <= MAX_APPLET_TRANSACTION_BODY_BYTES => bytes.to_vec(),
        Ok(bytes) => {
            record_applet_transaction("payload_too_large");
            applet_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!(
                    "transaction body is {} bytes; limit is {MAX_APPLET_TRANSACTION_BODY_BYTES} bytes",
                    bytes.len()
                ),
            );
            return;
        }
        Err(err) => {
            record_applet_transaction("bad_request");
            bad_request(res, format!("failed to read request body: {err}"));
            return;
        }
    };

    if let Err(error) = crate::precheck_applet_completion_envelope(&headers, &body_bytes) {
        unauthorized_code(res, error.code, error.message);
        return;
    }
    let value: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            record_applet_transaction("bad_request");
            bad_request(res, format!("invalid JSON body: {err}"));
            return;
        }
    };
    let request_hash = match arkret::canonical::canonical_sha256(&value) {
        Ok(hash) => hash,
        Err(err) => {
            record_applet_transaction("bad_request");
            bad_request(res, format!("non-canonical transaction JSON: {err}"));
            return;
        }
    };
    let body: AppletTransactionRequestBody = match serde_json::from_value(value) {
        Ok(body) => body,
        Err(err) => {
            record_applet_transaction("bad_request");
            bad_request(res, format!("invalid transaction body: {err}"));
            return;
        }
    };

    let AppletTransactionRequestBody::Authoring(authoring) = &body else {
        bad_request(res, "group content must use an accepted managed Device");
        return;
    };
    let authority = match request_authority(req, &headers) {
        Ok(authority) => authority,
        Err(error) => {
            unauthorized_code(res, error.code, error.message);
            return;
        }
    };
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let request = arkret::signatures::http_signature::SignedRequestParts {
        method: req.method().as_str().to_owned(),
        target_uri: request_target_uri(req, &headers, &authority, &path),
        authority,
        path,
        headers,
        body_digest: None,
    };
    let verified_completion = match state
        .edge
        .admit_managed_authoring_delivery(&request, &body_bytes, authoring)
        .await
    {
        Ok(completion) => completion,
        Err(error) => {
            let status = if error.code == "duplicate_conflict" {
                StatusCode::CONFLICT
            } else {
                StatusCode::UNAUTHORIZED
            };
            applet_error(res, status, error.code, error.message);
            return;
        }
    };
    let Some(record) = verified_completion.delivery_authentication_record() else {
        internal_error(
            res,
            "shared completion admission returned no authentication record",
        );
        return;
    };
    let replay = IdempotencyIdentity::applet_transaction(
        IdempotencyDirection::NodeToApplet,
        record.source_id.clone(),
        record.destination_id.clone(),
        record.idempotency_key.clone(),
    );
    let delivery_authentication_record_digest = match record.stable_digest() {
        Ok(digest) => digest.to_string(),
        Err(error) => {
            internal_error(res, error);
            return;
        }
    };

    // Recover the atomically retained terminal outcome even if a previous
    // process stopped after installing the original but before completing its
    // host claim-store row. Fresh authority checks already ran above.
    if let Some(outcome) = verified_completion.retained_outcome().cloned() {
        if let Err(error) = state
            .edge
            .install_verified_managed_completion(verified_completion)
        {
            internal_error(res, error.to_string());
            return;
        }
        record_applet_transaction("duplicate");
        res.render(Json(outcome));
        return;
    }

    // Authenticate before the first transaction-processing side effect. An
    // invalid Event proof must not leave a durable `pending` row behind. Once
    // authenticated, §7.3 requires the claim before invoking the handler.
    match authenticate_and_claim_transaction(
        body.clone(),
        state.idempotency.clone(),
        replay.clone(),
        request_hash.clone(),
        delivery_authentication_record_digest.clone(),
    )
    .await
    {
        Ok(Ok(TransactionClaim::Duplicate(response))) => {
            // Even cache hits retain this freshly verified signature's full
            // authentication record, atomically with the immutable original.
            if let Err(error) = state
                .edge
                .install_verified_managed_completion(verified_completion)
            {
                internal_error(res, error.to_string());
                return;
            }
            record_applet_transaction("duplicate");
            res.render(Json(response));
            return;
        }
        Ok(Ok(TransactionClaim::Pending)) => {
            record_applet_transaction("pending");
            res.render(Json(
                arkret_models_integration::AppletTransactionOutcome::Rejected {
                    rejections: Vec::new(),
                    retry_after_ms: Some(1000),
                },
            ));
            return;
        }
        Ok(Ok(TransactionClaim::Conflict)) => {
            record_applet_transaction("conflict");
            // Same (source_id, Idempotency-Key) with a different body:
            // applet-integration §7.3/§14 require the closed error code
            // `duplicate_conflict` (the registry has no `idempotency_conflict`).
            applet_error(
                res,
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "idempotency key was already used with a different request body",
            );
            return;
        }
        Ok(Ok(TransactionClaim::Claimed)) => {}
        Ok(Err(err)) => {
            record_applet_transaction("unauthorized");
            unauthorized(res, err);
            return;
        }
        Err(err) => {
            record_applet_transaction("internal_error");
            internal_error(res, err.to_string());
            return;
        }
    }

    let edge = state.edge.clone();
    match run_blocking(move || {
        edge.install_verified_managed_completion(verified_completion)?;
        Ok(AppletTransactionOutcome::Accepted {
            committed_event_refs: Vec::new(),
            rejections: Vec::new(),
            retry_after_ms: None,
        })
    })
    .await
    {
        Ok(response) => {
            if let Err(err) = record_transaction_outcome(
                state.idempotency.clone(),
                replay,
                request_hash,
                delivery_authentication_record_digest,
                response.clone(),
            )
            .await
            {
                tracing::warn!(error = %err, "failed to record idempotency outcome");
                record_applet_transaction("internal_error");
                internal_error(
                    res,
                    "transaction completed but its durable replay outcome was not recorded",
                );
                return;
            }
            record_applet_transaction("accepted");
            res.render(Json(response));
        }
        Err(err) => {
            if let Err(release_err) = release_transaction_claim(
                state.idempotency.clone(),
                replay,
                request_hash,
                delivery_authentication_record_digest,
            )
            .await
            {
                tracing::warn!(error = %release_err, "failed to release idempotency claim");
            }
            record_applet_transaction("internal_error");
            internal_error(res, err.to_string());
        }
    }
}

#[handler]
async fn applet_actor(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) =
        verify_http_applet_get_request(req, &state.config, state.did_authority.bindings())
    {
        unauthorized_code(res, err.code, err.message);
        return;
    }
    let actor_id = req.param::<String>("actor_id").unwrap_or_default();
    let handler = state.handler.clone();
    match run_blocking(move || handler.resolve_actor(&actor_id).map_err(BridgeError::from)).await {
        Ok(body) => res.render(Json(body)),
        Err(err) => internal_error(res, err.to_string()),
    }
}

#[handler]
async fn applet_realm(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) =
        verify_http_applet_get_request(req, &state.config, state.did_authority.bindings())
    {
        unauthorized_code(res, err.code, err.message);
        return;
    }
    let realm = req.param::<String>("realm_id_or_alias").unwrap_or_default();
    let handler = state.handler.clone();
    match run_blocking(move || handler.resolve_realm(&realm).map_err(BridgeError::from)).await {
        Ok(body) => res.render(Json(body)),
        Err(err) => internal_error(res, err.to_string()),
    }
}

#[handler]
async fn applet_protocol(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) =
        verify_http_applet_get_request(req, &state.config, state.did_authority.bindings())
    {
        unauthorized_code(res, err.code, err.message);
        return;
    }
    let protocol = req.param::<String>("protocol").unwrap_or_default();
    match state.handler.resolve_protocol(&protocol) {
        Ok(body) => res.render(Json(body)),
        Err(err) => internal_error(res, err.to_string()),
    }
}

#[handler]
async fn applet_third_party_unsupported(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) =
        verify_http_applet_get_request(req, &state.config, state.did_authority.bindings())
    {
        unauthorized_code(res, err.code, err.message);
        return;
    }
    unsupported_feature(
        res,
        "third_party user/location lookup is not implemented by this bridge",
    );
}

fn applet_state<'a>(depot: &'a Depot, res: &mut Response) -> Option<&'a AppletWebState> {
    match depot.get_typed::<AppletWebState>() {
        Ok(state) => Some(state),
        Err(_) => {
            internal_error(res, "applet web state missing");
            None
        }
    }
}

fn verify_http_applet_get_request(
    req: &Request,
    config: &Config,
    bindings: &AcceptedDidBindings,
) -> std::result::Result<(), HttpSignatureReject> {
    let headers = collect_headers(req);
    verify_http_applet_request(req, &headers, &[], config, bindings, false, None).map(|_| ())
}

fn verify_http_applet_request(
    req: &Request,
    headers: &[(String, String)],
    body: &[u8],
    config: &Config,
    bindings: &AcceptedDidBindings,
    require_content_digest: bool,
    realm_route: Option<&crate::realm_governance::RealmRoute>,
) -> std::result::Result<(), HttpSignatureReject> {
    verify_http_applet_request_with_scenario(
        req,
        headers,
        body,
        config,
        bindings,
        realm_route,
        if require_content_digest {
            HttpSignatureScenario::AppletTransactionV1
        } else {
            HttpSignatureScenario::ServiceToServiceV1
        },
        &[],
    )
}

fn verify_http_applet_request_with_scenario(
    req: &Request,
    headers: &[(String, String)],
    body: &[u8],
    config: &Config,
    bindings: &AcceptedDidBindings,
    realm_route: Option<&crate::realm_governance::RealmRoute>,
    scenario: HttpSignatureScenario,
    additional_required: &[&str],
) -> std::result::Result<(), HttpSignatureReject> {
    let signature_input_header = header_value_from(headers, "signature-input")
        .ok_or_else(|| http_signature_required("Signature-Input header is required"))?;
    let signature_input = parse_signature_input(&signature_input_header)
        .map_err(|err| http_signature_invalid(err.to_string()))?;
    let now = Utc::now();
    let now_unix_seconds = now.timestamp();
    let key_id_url = DidUrl::new(signature_input.key_id.clone()).map_err(|err| {
        http_signature_invalid(format!(
            "HTTP signature keyid `{}` is not a valid DID URL: {err}",
            signature_input.key_id
        ))
    })?;
    let signer_did = verification_method_did(&key_id_url).map_err(http_signature_invalid)?;
    let signer_id =
        project_did_to_core_id(&signer_did).map_err(|e| http_signature_invalid(e.to_string()))?;
    let expected_source = realm_route
        .map(|route| route.authority.current_service_id().clone())
        .unwrap_or(
            project_did_to_core_id(&config.arkret.trusted_server_did)
                .map_err(|e| http_signature_invalid(e.to_string()))?,
        );
    if signer_id != expected_source {
        return Err(http_signature_invalid(
            "HTTP signature keyid is not owned by the trusted server DID",
        ));
    }

    let origin = header_value_from(headers, SOURCE_SERVICE_ID_HEADER)
        .ok_or_else(|| http_signature_invalid("Source-Service-ID header is required"))?;
    let origin = DidCoreId::new(origin).map_err(|error| {
        http_signature_invalid(format!(
            "Source-Service-ID is not a valid service id: {error}"
        ))
    })?;
    if origin != expected_source {
        return Err(http_signature_invalid(
            "HTTP source differs from verified governance",
        ));
    }

    let destination = header_value_from(headers, DESTINATION_SERVICE_ID_HEADER)
        .ok_or_else(|| http_signature_invalid("Destination-Service-ID header is required"))?;
    let destination = DidCoreId::new(destination).map_err(|error| {
        http_signature_invalid(format!(
            "Destination-Service-ID is not a valid service id: {error}"
        ))
    })?;
    let bridge_service_id =
        project_did_to_core_id(&config.arkret.service_did).map_err(|error| {
            http_signature_invalid(format!(
                "configured bridge service DID cannot be projected: {error}"
            ))
        })?;
    if destination != bridge_service_id {
        return Err(http_signature_invalid(
            "HTTP signature destination service id does not match this bridge",
        ));
    }

    // The HTTP Message Signature is authenticated against the accepted
    // **source service** binding — the only purpose a bridge accepts. The
    // binding came from configuration at startup, so this is a pure in-memory
    // lookup, and a method with no acceptance fails closed instead of
    // triggering one.
    let public_key_bytes = if let Some(route) = realm_route {
        route
            .station_key(&key_id_url, now)
            .map_err(|e| http_signature_invalid(e.to_string()))?
            .ed25519_bytes()
            .map_err(|e| http_signature_invalid(e.to_string()))?
    } else {
        let accepted = bindings
            .source_service(&signer_did, &key_id_url, now)
            .map_err(|err| match err {
                BindingLookupError::Missing => http_signature_invalid(format!(
                    "verification method {key_id_url} is not trusted"
                )),
                BindingLookupError::NotUsable { .. } => http_signature_invalid(format!(
                    "source service verification method {key_id_url} is no longer accepted: {err}"
                )),
            })?;
        let bytes = public_key_material_from_binding(&accepted, &key_id_url)
            .map_err(|err| http_signature_invalid(err.to_string()))?
            .ed25519_bytes()
            .map_err(|err| http_signature_invalid(err.to_string()))?;
        bytes
    };
    let public_key = public_key_from_bytes(&public_key_bytes)
        .map_err(|err| http_signature_invalid(err.to_string()))?;
    let authority = request_authority(req, headers)?;
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let target_uri = request_target_uri(req, headers, &authority, &path);
    let policy = SignatureVerificationPolicy::for_scenario(scenario, additional_required)
        .map_err(|error| map_http_signature_error(HttpMessageVerificationError::Policy(error)))?;
    verify_signed_http_message(
        req.method().as_str(),
        &target_uri,
        &authority,
        &path,
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        body,
        &public_key,
        &policy,
        now_unix_seconds,
    )
    .map_err(map_http_signature_error)?;
    Ok(())
}

/// Structurally validate every Event proof in a pushed transaction.
///
/// This path performs **no** DID authority call and verifies **no** Event proof
/// signature, and that is the ruling, not an omission
/// (`review/spec-done` — service-local DID authority call sites): §4's
/// exclusion list says an ordinary or high-risk Event write creates no DID
/// authority call and that a device key MUST come from an accepted PCR
/// authorization chain. A bridge cannot reach that chain, so resolving the
/// signer here would prove only that a key appears in some DID document while
/// reading as if the signer had been independently admitted.
///
/// The signer authority of an inbound Event is therefore carried by the source
/// Arkret node: it completed admission and vouches for this exact body through
/// the RFC 9421 HTTP Message Signature that
/// [`crate::did_binding::DidAuthority::service_verification_method`] checks
/// against the operator-configured anchor before this function runs.
///
/// What is still enforced here is everything a bridge can decide on its own:
/// exactly one production producer proof per Event, a well-formed proof
/// binding, and a signer DID that projects to the Event's `executed_by` /
/// `actor_id`. A mismatch is a malformed push and fails closed.
fn verify_transaction_events(
    body: &AppletTransactionRequestBody,
) -> std::result::Result<(), String> {
    let body = match body {
        AppletTransactionRequestBody::Events(body) => body,
        // An authoring completion carries no producer Events of its own; its
        // bindings were already checked at the delivery boundary.
        AppletTransactionRequestBody::Authoring(_) => return Ok(()),
    };
    for event in &body.events {
        let Some(proof) = event.producer_proof.as_ref() else {
            return Err(format!(
                "event {} must carry exactly one producer proof",
                event.event_id
            ));
        };
        let expected_signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
        // The bridge checks immutable content-address consistency against the
        // algorithm committed by the unique producer proof. Trusted Realm-suite
        // admission remains the source Arkret node's responsibility; the bridge
        // never infers governance state from the EventId prefix.
        let selector_suite = proof.event_digest.digest_suite().map_err(|error| {
            format!(
                "event {} producer digest suite is invalid: {error}",
                event.event_id
            )
        })?;
        event
            .validate_proof_bindings_with_digest_suite(selector_suite)
            .map_err(|err| format!("event {} proof binding failed: {err}", event.event_id))?;
        proof
            .validate_production()
            .map_err(|err| format!("event {} proof is not production: {err}", event.event_id))?;
        let signer_did = verification_method_did(&proof.verification_method)?;
        let signer_actor_id =
            arkret::project_did_to_core_id(&signer_did).map_err(|error| error.to_string())?;
        if &signer_actor_id != expected_signer.signing_principal_id() {
            return Err(format!(
                "event {} proof signer DID does not match actor_id/executed_by",
                event.event_id
            ));
        }
    }
    Ok(())
}

/// Accept the operator-configured HTTP Message Signature trust anchors as
/// `service`-purpose bindings, once, at startup.
///
/// These are the *source service* keys of the pushing Arkret node, and the only
/// bindings a bridge holds: it registers no DID authority call site, so nothing
/// on this path may accept a binding the operator did not configure.
fn seed_source_service_bindings(authority: &DidAuthority, config: &Config) -> Result<()> {
    let now = Utc::now();
    for method in &config.arkret.trusted_verification_methods {
        // Normalize every accepted key form (raw / multibase / JWK) to the
        // multibase representation a DID document publishes, so the pinned
        // document is exactly what the SDK verifier expects to read back.
        let key_bytes = method.public_key.ed25519_bytes().map_err(|err| {
            BridgeError::Config(format!(
                "arkret.trusted_verification_methods[] key for `{}` \
                 is not a usable Ed25519 key: {err}",
                method.verification_method,
            ))
        })?;
        authority
            .accept_configured_source_service_key(
                &method.verification_method,
                &arkret::ed25519_pubkey_to_did_key_multibase(&key_bytes),
                now,
            )
            .map_err(BridgeError::Config)?;
    }
    Ok(())
}

fn collect_headers(req: &Request) -> Vec<(String, String)> {
    req.headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

fn header_value(req: &Request, name: &str) -> Option<String> {
    header_value_from(&collect_headers(req), name)
}

fn header_value_from(headers: &[(String, String)], name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let values: Vec<&str> = headers
        .iter()
        .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(&lower))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

fn request_authority(
    req: &Request,
    headers: &[(String, String)],
) -> std::result::Result<String, HttpSignatureReject> {
    header_value_from(headers, "host")
        .or_else(|| {
            req.uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .ok_or_else(|| http_signature_invalid("request authority/Host is required"))
}

fn request_target_uri(
    req: &Request,
    headers: &[(String, String)],
    authority: &str,
    path: &str,
) -> String {
    let uri = req.uri();
    if uri.scheme().is_some() && uri.authority().is_some() {
        return uri.to_string();
    }
    let scheme = header_value_from(headers, "x-forwarded-proto")
        .and_then(|value| value.split(',').next().map(str::trim).map(str::to_owned))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http".to_owned());
    format!("{scheme}://{authority}{path}")
}

/// Render the RFC 9457 Problem Details response with a registry error code. The protocol
/// surface (`/_arkret/edge/applet/*`) is part of the universal failure surface
/// in `operations-error-mapping.json`, so the `code` must come from the closed
/// `error-code-registry.json` set rather than being a free-form string.
pub(crate) fn applet_error(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
) {
    let envelope = arkret_wire::Problem::from_code(code, message)
        .with_instance(arkret_wire::new_prefixed_uuid7("ak:request:"));
    let problem = envelope.with_status(status.as_u16());
    let mut output = salvo::http::Problem::new(status)
        .kind(problem.problem_type)
        .title(problem.title)
        .detail(problem.detail)
        .with_extensions(
            problem
                .extensions
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        );
    if let Some(instance) = problem.instance {
        output = output.instance(instance);
    }
    res.render(output);
}

fn bad_request(res: &mut Response, message: impl Into<String>) {
    applet_error(res, StatusCode::BAD_REQUEST, "json_invalid", message);
}

fn unauthorized(res: &mut Response, message: impl Into<String>) {
    applet_error(res, StatusCode::UNAUTHORIZED, "signature_invalid", message);
}

fn unauthorized_code(res: &mut Response, code: &'static str, message: impl Into<String>) {
    applet_error(res, StatusCode::UNAUTHORIZED, code, message);
}

fn http_signature_required(message: impl Into<String>) -> HttpSignatureReject {
    HttpSignatureReject {
        code: "http_signature_required",
        message: message.into(),
    }
}

fn http_signature_invalid(message: impl Into<String>) -> HttpSignatureReject {
    HttpSignatureReject {
        code: "http_signature_invalid",
        message: message.into(),
    }
}

fn signature_window_invalid(message: impl Into<String>) -> HttpSignatureReject {
    HttpSignatureReject {
        code: "signature_window_invalid",
        message: message.into(),
    }
}

fn map_http_signature_error(err: HttpMessageVerificationError) -> HttpSignatureReject {
    let message = err.to_string();
    match err {
        HttpMessageVerificationError::MissingHeader(_) => http_signature_required(message),
        HttpMessageVerificationError::Policy(
            SignaturePolicyError::InvalidValidityWindow
            | SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => signature_window_invalid(message),
        HttpMessageVerificationError::Policy(_)
        | HttpMessageVerificationError::Signature(_)
        | HttpMessageVerificationError::ContentEncodingNotAllowed
        | HttpMessageVerificationError::NonCanonicalJson(_) => http_signature_invalid(message),
    }
}

fn internal_error(res: &mut Response, message: impl Into<String>) {
    applet_error(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        message,
    );
}

fn unsupported_feature(res: &mut Response, message: impl Into<String>) {
    applet_error(
        res,
        StatusCode::NOT_IMPLEMENTED,
        "unsupported_feature",
        message,
    );
}

#[cfg(test)]
mod tests {
    //! Discovery uses configured Service anchors. Completion delivery additionally
    //! verifies fresh governance/private-read authority, after exact content
    //! digest and canonical wire checks and before any cache or journal write.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret::signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};
    use arkret::{Did, DidCoreId, Event, RealmId, ScopeRef, TrustDomainId};
    use chrono::DateTime;

    use super::*;

    #[derive(Debug, Default)]
    struct CountingIdempotencyStore {
        claims: AtomicUsize,
    }

    impl TransactionIdempotencyStore<AppletTransactionOutcome> for CountingIdempotencyStore {
        type Error = BridgeError;

        fn claim(
            &self,
            _identity: &IdempotencyIdentity,
            _body_digest: &str,
            _delivery_authentication_record_digest: &str,
        ) -> Result<TransactionClaim<AppletTransactionOutcome>> {
            self.claims.fetch_add(1, Ordering::SeqCst);
            Ok(TransactionClaim::Claimed)
        }

        fn record(
            &self,
            _identity: &IdempotencyIdentity,
            _body_digest: &str,
            _delivery_authentication_record_digest: &str,
            _outcome: &AppletTransactionOutcome,
        ) -> Result<()> {
            Ok(())
        }

        fn release(
            &self,
            _identity: &IdempotencyIdentity,
            _body_digest: &str,
            _delivery_authentication_record_digest: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    // ========================================================================
    // Fixtures
    // ========================================================================

    fn signer(seed: u8, actor: &Did, verification_method: &DidUrl) -> Ed25519PayloadSigner {
        Ed25519PayloadSigner::from_did_key_seed(
            [seed; 32],
            actor.clone(),
            verification_method.clone(),
        )
    }

    fn public_key_bytes(seed: u8) -> [u8; 32] {
        signer(seed, &actor_did(), &actor_verification_method())
            .verifying_key()
            .to_bytes()
    }

    fn trust_domain() -> TrustDomainId {
        TrustDomainId::new("ak:trust_domain:bridge.example".to_owned()).expect("trust domain")
    }

    fn actor_did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).expect("actor did")
    }

    fn actor_verification_method() -> DidUrl {
        DidUrl::new(format!("{}#key-1", actor_did())).expect("did url")
    }

    fn actor_id(did: &Did) -> DidCoreId {
        arkret::project_did_to_core_id(did).expect("actor core id")
    }

    fn server_did() -> Did {
        Did::new("did:webvh:z6mkfixture:server.example".to_owned()).expect("server did")
    }

    fn server_verification_method() -> DidUrl {
        DidUrl::new(format!("{}#tx-1", server_did())).expect("did url")
    }

    fn authority() -> DidAuthority {
        DidAuthority::new(trust_domain()).expect("authority")
    }

    /// One Event signed by `seed`'s key under `verification_method`.
    fn signed_event(actor: &Did, verification_method: &DidUrl, seed: u8, seq: u64) -> Event {
        let realm =
            RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").expect("realm");
        let event = arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id: realm },
            actor_id(actor),
            arkret::project_did_to_core_id(&server_did()).expect("server core id"),
            json!({ "body": format!("hello {seq}") }),
        )
        .expect("event");
        // A received Event arrives finalized and signed, so the fixture reaches
        // the verifier the same way.
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret::canonical::DigestSuite::Sha256,
        )
        .expect("fixture envelope finalizes");
        sign_event(
            &mut event,
            &signer(seed, actor, verification_method),
            SignEventOptions::new(),
        )
        .expect("sign event");
        event.into_event()
    }

    fn transaction(events: Vec<Event>) -> AppletTransactionRequestBody {
        AppletTransactionRequestBody::Events(
            arkret_models_integration::AppletEventTransactionRequestBody {
                applet_id: arkret::AppletId::new(
                    "ak:applet:01904100-0000-7000-8000-000000000001".to_owned(),
                )
                .expect("applet id"),
                source_id: arkret::project_did_to_core_id(&server_did()).expect("server core id"),
                events,
                committed_events: Vec::new(),
                signals: Vec::new(),
            },
        )
    }

    fn seed_source_service(authority: &DidAuthority, seed: u8, now: DateTime<Utc>) {
        authority
            .accept_configured_source_service_key(
                &server_verification_method(),
                &arkret::ed25519_pubkey_to_did_key_multibase(&public_key_bytes(seed)),
                now,
            )
            .expect("source service binding");
    }

    // ========================================================================
    // Event proofs are validated structurally, never resolved.
    // ========================================================================

    #[test]
    fn a_well_formed_transaction_is_accepted_without_any_signer_binding() {
        let body = transaction(vec![
            signed_event(&actor_did(), &actor_verification_method(), 42, 1),
            signed_event(&actor_did(), &actor_verification_method(), 42, 2),
        ]);
        verify_transaction_events(&body).expect("structurally valid transaction");
    }

    #[test]
    fn an_event_proof_signed_by_a_foreign_did_is_rejected() {
        // The Event's `actor_id` and the proof's verification method disagree.
        let foreign = Did::new("did:webvh:z6mkmallory:mallory.example".to_owned()).expect("did");
        let foreign_method = DidUrl::new(format!("{foreign}#key-1")).expect("did url");
        let mut event = signed_event(&foreign, &foreign_method, 42, 1);
        event.actor_id = arkret::ActorId::service(actor_id(&actor_did()));

        let err = verify_transaction_events(&transaction(vec![event]))
            .expect_err("signer/actor mismatch must be rejected");
        assert!(
            err.contains("proof binding failed") || err.contains("does not match"),
            "{err}"
        );
    }

    #[test]
    fn an_event_without_producer_proof_is_rejected() {
        let mut event = signed_event(&actor_did(), &actor_verification_method(), 42, 1);
        event.producer_proof = None;
        let err = verify_transaction_events(&transaction(vec![event]))
            .expect_err("a proofless event must be rejected");
        assert!(err.contains("exactly one producer proof"), "{err}");
    }

    #[test]
    fn an_empty_event_list_is_accepted() {
        verify_transaction_events(&transaction(Vec::new())).expect("empty transaction");
    }

    #[tokio::test]
    async fn a_malformed_event_proof_creates_no_idempotency_record() {
        let mut event = signed_event(&actor_did(), &actor_verification_method(), 42, 1);
        event.producer_proof = None;
        let store = Arc::new(CountingIdempotencyStore::default());
        let replay = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            project_did_to_core_id(&server_did()).expect("server core id"),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebridge").unwrap(),
            "invalid-proof",
        );

        let result = authenticate_and_claim_transaction(
            transaction(vec![event]),
            store.clone(),
            replay,
            "sha256:unused-by-counting-store".to_owned(),
            "source-anchor".to_owned(),
        )
        .await
        .expect("authentication worker");

        assert!(
            result.is_err(),
            "a malformed proof must fail authentication"
        );
        assert_eq!(
            store.claims.load(Ordering::SeqCst),
            0,
            "a malformed proof must not create an idempotency record"
        );
    }

    // ========================================================================
    // The HTTP-signature anchor is configuration, never a lookup.
    // ========================================================================

    #[test]
    fn the_configured_anchor_answers_the_http_signature_lookup() {
        let authority = authority();
        let now = Utc::now();
        seed_source_service(&authority, 7, now);

        let accepted = authority
            .bindings()
            .source_service(&server_did(), &server_verification_method(), now)
            .expect("source service binding");
        assert_eq!(
            public_key_material_from_binding(&accepted, &server_verification_method())
                .expect("material")
                .ed25519_bytes()
                .expect("bytes"),
            public_key_bytes(7)
        );
    }

    #[test]
    fn an_unconfigured_verification_method_has_no_binding_to_fall_back_on() {
        let authority = authority();
        let now = Utc::now();
        assert_eq!(
            authority
                .bindings()
                .source_service(&actor_did(), &actor_verification_method(), now),
            Err(BindingLookupError::Missing)
        );
        assert!(
            authority
                .service_verification_method(&actor_verification_method(), now)
                .is_err(),
            "a bridge has no resolver to reach for an unconfigured method"
        );
    }

    #[test]
    fn rotating_the_source_service_key_replaces_the_http_signature_material() {
        let authority = authority();
        let now = Utc::now();

        seed_source_service(&authority, 7, now);
        // Operator rotates the configured anchor.
        seed_source_service(&authority, 8, now);

        let after = authority
            .bindings()
            .source_service(&server_did(), &server_verification_method(), now)
            .expect("binding");
        assert_eq!(
            public_key_material_from_binding(&after, &server_verification_method())
                .expect("material")
                .ed25519_bytes()
                .expect("bytes"),
            public_key_bytes(8),
            "the rotated key must replace, not shadow, the previous one"
        );
    }

    // ========================================================================
    // The operator invalidation endpoint is a real runtime trigger for §5.6.
    // These go through the mounted route and HTTP body parsing, not the
    // `invalidate_did` method in isolation.
    // ========================================================================

    use salvo::test::{ResponseExt, TestClient};

    #[tokio::test]
    async fn every_edge_route_selects_before_authentication_or_body_parsing() {
        let service = salvo::Service::new(applet_routes());
        let routes = [
            ("ping", ServiceOperationId::EDGE_APPLET_READ_PING_V1),
            ("describe", ServiceOperationId::EDGE_APPLET_READ_DESCRIBE_V1),
            (
                "transactions",
                ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            ),
            (
                "actors/invalid",
                ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE_V1,
            ),
            (
                "realms/invalid",
                ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE_V1,
            ),
            (
                "protocols/slack",
                ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA_V1,
            ),
            (
                "third_party/users",
                ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_READ_LIST_V1,
            ),
            (
                "third_party/locations",
                ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_READ_LIST_V1,
            ),
        ];
        for (path, operation) in routes {
            let url = format!("https://applet.example/_arkret/edge/applet/{path}");
            for selector in [None, Some("wrong"), Some(operation)] {
                let mut request = if path == "transactions" {
                    TestClient::post(&url).body("{invalid JSON")
                } else {
                    TestClient::get(&url)
                };
                if let Some(value) = selector {
                    request = request.add_header("arkret-operation", value, false);
                    if value == operation {
                        request = request.add_header("arkret-operation", value, false);
                    }
                }
                let mut response = request.send(&service).await;
                let expected = if selector.is_none() {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::UNPROCESSABLE_ENTITY
                };
                assert_eq!(response.status_code, Some(expected), "{path}: {selector:?}");
                let problem: arkret_wire::Problem = response.take_json().await.unwrap();
                assert_eq!(
                    problem.code(),
                    if selector.is_none() {
                        "operation_selector_required"
                    } else {
                        "unsupported_operation_version"
                    }
                );
            }
        }
    }

    const INVALIDATE_URL: &str = "http://127.0.0.1/admin/did-bindings/invalidate";

    fn admin_service(authority: Arc<DidAuthority>) -> salvo::Service {
        salvo::Service::new(Router::new().push(admin_did_bindings_router(AdminWebState {
            did_authority: authority,
        })))
    }

    #[tokio::test]
    async fn the_admin_endpoint_invalidates_the_accepted_binding() {
        let authority = Arc::new(authority());
        let now = Utc::now();
        seed_source_service(&authority, 7, now);
        assert!(
            authority
                .bindings()
                .source_service(&server_did(), &server_verification_method(), now)
                .is_ok(),
            "precondition: the seeded binding answers lookups"
        );
        let service = admin_service(authority.clone());

        let mut response = TestClient::post(INVALIDATE_URL)
            .json(&json!({ "did": server_did().to_string() }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body: Value = response.take_json().await.expect("json body");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["invalidated_bindings"], json!(1));

        assert_eq!(
            authority
                .bindings()
                .source_service(&server_did(), &server_verification_method(), now),
            Err(crate::did_binding::BindingLookupError::Missing),
            "the trigger must drop the acceptance immediately"
        );
    }

    #[tokio::test]
    async fn a_matching_trust_domain_guard_still_sweeps() {
        let authority = Arc::new(authority());
        let now = Utc::now();
        seed_source_service(&authority, 7, now);
        let service = admin_service(authority.clone());

        let mut response = TestClient::post(INVALIDATE_URL)
            .json(&json!({
                "did": server_did().to_string(),
                "trust_domain": trust_domain().as_str(),
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body: Value = response.take_json().await.expect("json body");
        assert_eq!(body["invalidated_bindings"], json!(1));
    }

    #[tokio::test]
    async fn a_foreign_trust_domain_is_refused_and_the_binding_survives() {
        let authority = Arc::new(authority());
        let now = Utc::now();
        seed_source_service(&authority, 7, now);
        let service = admin_service(authority.clone());

        let response = TestClient::post(INVALIDATE_URL)
            .json(&json!({
                "did": server_did().to_string(),
                "trust_domain": "ak:trust_domain:other.example",
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::CONFLICT));
        assert!(
            authority
                .bindings()
                .source_service(&server_did(), &server_verification_method(), now)
                .is_ok(),
            "a refused sweep must not touch the store"
        );
    }

    #[tokio::test]
    async fn an_invalid_did_is_rejected_without_touching_the_store() {
        let authority = Arc::new(authority());
        let now = Utc::now();
        seed_source_service(&authority, 7, now);
        let service = admin_service(authority.clone());

        let response = TestClient::post(INVALIDATE_URL)
            .json(&json!({ "did": "not-a-did" }))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        assert!(
            authority
                .bindings()
                .source_service(&server_did(), &server_verification_method(), now)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn sweeping_a_did_with_no_acceptance_is_an_idempotent_success() {
        let authority = Arc::new(authority());
        let service = admin_service(authority);

        let mut response = TestClient::post(INVALIDATE_URL)
            .json(&json!({ "did": actor_did().to_string() }))
            .send(&service)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::OK),
            "an operator retrying a revocation must not read the retry as a failure"
        );
        let body: Value = response.take_json().await.expect("json body");
        assert_eq!(body["invalidated_bindings"], json!(0));
    }

    #[tokio::test]
    async fn completion_route_checks_exact_digest_and_canonical_wire_before_json_or_authority() {
        use arkret::http_signature::{ContentDigest, ContentDigestAlgorithm};
        struct UntouchedJournal {
            reads: AtomicUsize,
            writes: AtomicUsize,
        }
        impl crate::AuthoringStore for UntouchedJournal {
            fn load(&self, _: &str) -> Result<Option<String>> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            fn compare_exchange_batch(
                &self,
                _: &[(String, Option<String>)],
                _: &[(String, Option<String>)],
            ) -> Result<bool> {
                self.writes.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
            fn entries_with_prefix(&self, _: &str) -> Result<Vec<(String, String)>> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }
        let journal = Arc::new(UntouchedJournal {
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        });
        let config: Config = serde_json::from_value(json!({
            "bridge":{"bridge_id":"envelope-priority"},
            "arkret":{
                "server_url":"https://station.example", "applet_base_url":"https://bridge.example",
                "service_did":"did:webvh:z6mkbridge:bridge.example", "trusted_server_did":"did:webvh:z6mkstation:station.example",
                "trust_domain":"ak:trust_domain:example.net", "applet_id":"ak:applet:01904100-0000-7000-8000-000000000001",
                "signing_key_seed_hex":"11".repeat(32), "verification_method_fragment":"#key-1",
                "applet_namespaces":{"actors":[],"realms":[],"handles":[]},
                "managed_actor_authoring":{"principal_endpoint":"https://actors.example","key_encryption_key_hex":"22".repeat(32)}
            }
        })).unwrap();
        let (sender, _) = tokio::sync::mpsc::channel(1);
        let edge =
            Arc::new(crate::ArkretEdge::new(Arc::new(config), journal.clone(), sender).unwrap());
        let claims = Arc::new(CountingIdempotencyStore::default());
        let service = salvo::Service::new(applet_completion_router(edge, claims.clone()).unwrap());
        let url = "https://bridge.example/_arkret/edge/applet/transactions".to_owned();
        for (label, body, mutation, code) in [
            ("all-missing", "{invalid", "all", "http_signature_required"),
            (
                "signature-missing",
                "{}",
                "signature",
                "http_signature_required",
            ),
            (
                "signature-input-missing",
                "{}",
                "signature-input",
                "http_signature_required",
            ),
            (
                "only-digest-missing",
                "{invalid",
                "content-digest",
                "http_signature_invalid",
            ),
            (
                "wrong-exact-digest",
                "{invalid",
                "wrong-digest",
                "http_signature_invalid",
            ),
            ("malformed-json", "{invalid", "", "http_signature_invalid"),
            ("noncanonical-json", "{ }", "", "http_signature_invalid"),
            (
                "source-missing",
                "{}",
                "source-service-id",
                "http_signature_invalid",
            ),
            (
                "destination-missing",
                "{}",
                "destination-service-id",
                "http_signature_invalid",
            ),
            (
                "idempotency-missing",
                "{}",
                "idempotency-key",
                "http_signature_invalid",
            ),
        ] {
            let parsed = url::Url::parse(&url).unwrap();
            let authority = parsed.host_str().unwrap().to_owned();
            let digest = ContentDigest::compute(body.as_bytes(), ContentDigestAlgorithm::Sha256);
            let mut parts = arkret::http_signature::SignedRequestParts {
                method: "POST".into(),
                target_uri: url.clone(),
                authority,
                path: parsed.path().into(),
                headers: vec![
                    (
                        "arkret-operation".into(),
                        ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1.into(),
                    ),
                    (
                        "source-service-id".into(),
                        "ak:did_core:webvh:z6mkstation".into(),
                    ),
                    (
                        "destination-service-id".into(),
                        "ak:did_core:webvh:z6mkbridge".into(),
                    ),
                    ("idempotency-key".into(), "envelope-before-json".into()),
                    ("content-digest".into(), digest.wire_value.clone()),
                ],
                body_digest: Some(digest.wire_value),
            };
            let signed = arkret::http_signature::sign_http_message_for_scenario(
                &parts,
                arkret::http_signature::HttpSignatureScenario::AppletTransactionV1,
                &[],
                "sig1",
                "did:webvh:z6mkstation:station.example#key-1",
                chrono::Utc::now().timestamp(),
                &arkret::http_signature::signing_key_from_seed(&[0x62; 32]),
            )
            .unwrap();
            parts
                .headers
                .push(("signature-input".into(), signed.signature_input_header));
            parts
                .headers
                .push(("signature".into(), signed.signature_header));
            if mutation == "all" {
                parts.headers.retain(|(name, _)| name == "arkret-operation");
            } else if mutation == "wrong-digest" {
                parts.headers.retain(|(name, _)| name != "content-digest");
                parts.headers.push((
                    "content-digest".into(),
                    ContentDigest::compute(b"{}", ContentDigestAlgorithm::Sha256).wire_value,
                ));
            } else if !mutation.is_empty() {
                parts.headers.retain(|(name, _)| name != mutation);
            }
            let mut request = TestClient::post(&url).body(body);
            for (name, value) in parts.headers {
                request = request.add_header(
                    salvo::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value,
                    true,
                );
            }
            let mut response = request.send(&service).await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::UNAUTHORIZED),
                "{label}"
            );
            let problem: arkret_wire::Problem = response.take_json().await.unwrap();
            assert_eq!(problem.code(), code);
            if mutation == "content-digest" || mutation == "wrong-digest" {
                assert!(
                    problem.detail.to_ascii_lowercase().contains("digest"),
                    "Digest failure must precede malformed business JSON: {label}: {}",
                    problem.detail
                );
            }
            assert_eq!(claims.claims.load(Ordering::SeqCst), 0);
            assert_eq!(
                journal.reads.load(Ordering::SeqCst),
                0,
                "authority lookup is gated behind local custody reads"
            );
            assert_eq!(journal.writes.load(Ordering::SeqCst), 0);
        }
    }
}
