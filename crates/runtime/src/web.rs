//! salvo HTTP service: health check / metrics / provisioning, plus mounting
//! the arkret applet routes (`/_arkret/edge/applet/*`) to receive event pushes
//! from the arkret server.

use std::sync::{Arc, OnceLock};

use ::metrics::{counter, describe_counter};
use arkret::identity::public_key_material_from_binding;
use arkret::signatures::http_signature::{
    Component, HttpMessageVerificationError, SignatureInput, SignaturePolicyError,
    SignatureVerificationPolicy, parse_signature_input, public_key_from_bytes,
    verify_signed_http_message,
};
use arkret::{
    AppletHandler, IdempotencyDirection, IdempotencyIdentity, RejectedItem, TransactionClaim,
    TransactionIdempotencyStore,
};
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_integration::AppletTransactionOutcome;
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
use crate::db::{DbEventDedupStore, DbTransactionIdempotencyStore};
use crate::did_binding::{
    AcceptedDidBindings, BindingLookupError, DidAuthority, verification_method_did,
};
use crate::error::{BridgeError, Result};
use crate::idempotency::EventDedupStore;
use crate::run_blocking;

static PROMETHEUS_HANDLE: OnceLock<std::result::Result<PrometheusHandle, String>> = OnceLock::new();
const APPLET_TRANSACTION_SIGNATURE_MAX_LIFETIME_SECS: i64 = 300;
const APPLET_TRANSACTION_SIGNATURE_MAX_CLOCK_SKEW_SECS: i64 = 30;
/// Upper bound on the inbound edge `transactions` body, mirroring the webhook
/// surface's `MAX_WEBHOOK_BODY_BYTES` (1 MiB). Without it the body is buffered
/// into memory in full *before* signature verification, an unauthenticated
/// memory-pressure vector on any deployment that exposes this surface.
const MAX_APPLET_TRANSACTION_BODY_BYTES: usize = 1024 * 1024;
const SOURCE_SERVICE_ID_HEADER: &str = "source-service-id";
const DESTINATION_SERVICE_ID_HEADER: &str = "destination-service-id";

/// Start the web service and run it blocking. `extra` is each app adapter's
/// webhook routes (optional).
pub async fn serve(ctx: Arc<BridgeContext>, extra: Option<Router>) -> Result<()> {
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
    let dedup: Arc<dyn EventDedupStore> = Arc::new(DbEventDedupStore::new(ctx.db.clone())?);
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
        dedup,
        ctx.handled_event_kinds(),
        did_authority.clone(),
    )?);
    let applet = applet_router(AppletWebState {
        handler,
        config: ctx.config.clone(),
        idempotency,
        did_authority,
    });

    // Internal plane: the trusted applet protocol surface
    // (`/_arkret/edge/applet/*`) and the ops surface (`/health` + `/metrics`)
    // share one loopback-by-default acceptor. Keeping these off the public
    // webhook bind means "no reverse proxy configured" still isolates the
    // trusted and ops planes from the public network (BRG-06-004).
    let admin_router = Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("metrics").get(metrics_endpoint))
        .push(applet);

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
        Ok(handle)
    }) {
        Ok(handle) => Ok(handle),
        Err(err) => Err(err.clone()),
    }
}

fn record_applet_transaction(result: &'static str) {
    counter!("arkret_bridge_applet_transactions_total", "result" => result).increment(1);
}

#[derive(Clone)]
struct AppletWebState {
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

struct VerifiedAppletHttpRequest {
    source_service_id: String,
    destination_service_id: String,
    key_id: String,
    source_key_state_digest: String,
    content_digest: Option<String>,
    covered_components: Vec<String>,
    created: i64,
    expires: i64,
    canonical_message_digest: String,
}

struct HttpSignatureReject {
    code: &'static str,
    message: String,
}

fn applet_router(state: AppletWebState) -> Router {
    Router::with_path("_arkret/edge/applet")
        .hoop(affix_state::inject(state))
        .push(Router::with_path("ping").get(applet_ping))
        .push(Router::with_path("describe").get(applet_describe))
        .push(Router::with_path("transactions").post(applet_transactions))
        .push(Router::with_path("actors/{actor_id}").get(applet_actor))
        .push(Router::with_path("realms/{realm_id_or_alias}").get(applet_realm))
        .push(Router::with_path("protocols/{protocol}").get(applet_protocol))
        // The applet edge surface declares eight operations; the third_party
        // user/location lookups are not backed by a server-side discovery index
        // here. Per applet-integration §15 an unimplemented surface MUST return a
        // structured `unsupported_feature` rather than fall through to a bare 404.
        .push(Router::with_path("third_party/users").get(applet_third_party_unsupported))
        .push(Router::with_path("third_party/locations").get(applet_third_party_unsupported))
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
    let Some(idempotency_key) = header_value(req, "idempotency-key")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        record_applet_transaction("bad_request");
        bad_request(res, "Idempotency-Key header is required");
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

    let verified = match verify_http_transaction_request(
        req,
        &headers,
        &body_bytes,
        &state.config,
        state.did_authority.bindings(),
    ) {
        Ok(verified) => verified,
        Err(err) => {
            record_applet_transaction("unauthorized");
            unauthorized_code(res, err.code, err.message);
            return;
        }
    };

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

    let source = body.source_service_id.to_string();
    if source != verified.source_service_id {
        record_applet_transaction("unauthorized");
        unauthorized_code(
            res,
            "http_signature_invalid",
            "transaction source_service_id does not match signed origin service DID",
        );
        return;
    }
    if source != state.config.arkret.trusted_server_did {
        record_applet_transaction("unauthorized");
        unauthorized_code(
            res,
            "http_signature_invalid",
            "transaction source_service_id is not trusted",
        );
        return;
    }

    let destination = verified.destination_service_id.clone();
    let replay = IdempotencyIdentity::applet_transaction(
        IdempotencyDirection::NodeToApplet,
        source.clone(),
        destination,
        idempotency_key.clone(),
    );
    let delivery_authentication_record_digest = match build_delivery_authentication_record_digest(
        &verified,
        &request_hash,
        &idempotency_key,
    ) {
        Ok(anchor) => anchor,
        Err(err) => {
            record_applet_transaction("internal_error");
            internal_error(res, err);
            return;
        }
    };

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
            record_applet_transaction("duplicate");
            res.render(Json(response));
            return;
        }
        Ok(Ok(TransactionClaim::Pending)) => {
            record_applet_transaction("pending");
            res.render(Json(arkret_models_integration::AppletTransactionOutcome {
                ok: false,
                rejected: Vec::new(),
                retry_after_ms: Some(1000),
            }));
            return;
        }
        Ok(Ok(TransactionClaim::Conflict)) => {
            record_applet_transaction("conflict");
            // Same (source_service_id, Idempotency-Key) with a different body:
            // applet-integration §7.3/§14 require the closed error code
            // `duplicate_conflict` (the registry has no `idempotency_conflict`).
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(arkret_models_integration::AppletTransactionOutcome {
                ok: false,
                rejected: vec![RejectedItem {
                    event_id: None,
                    reason_code: arkret_wire::ReasonCode::from_wire(
                        arkret_wire::ReasonCode::DUPLICATE_CONFLICT,
                    ),
                    retry_after_ms: None,
                }],
                retry_after_ms: None,
            }));
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

    let handler = state.handler.clone();
    let idempotency_key_for_handler = idempotency_key.clone();
    match run_blocking(move || {
        handler
            .handle_transaction(&idempotency_key_for_handler, body)
            .map_err(BridgeError::from)
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

fn verify_http_transaction_request(
    req: &Request,
    headers: &[(String, String)],
    body: &[u8],
    config: &Config,
    bindings: &AcceptedDidBindings,
) -> std::result::Result<VerifiedAppletHttpRequest, HttpSignatureReject> {
    verify_http_applet_request(req, headers, body, config, bindings, true)
}

fn verify_http_applet_get_request(
    req: &Request,
    config: &Config,
    bindings: &AcceptedDidBindings,
) -> std::result::Result<(), HttpSignatureReject> {
    let headers = collect_headers(req);
    verify_http_applet_request(req, &headers, &[], config, bindings, false).map(|_| ())
}

fn verify_http_applet_request(
    req: &Request,
    headers: &[(String, String)],
    body: &[u8],
    config: &Config,
    bindings: &AcceptedDidBindings,
    require_content_digest: bool,
) -> std::result::Result<VerifiedAppletHttpRequest, HttpSignatureReject> {
    let signature_input_header = header_value_from(headers, "signature-input")
        .ok_or_else(|| http_signature_required("Signature-Input header is required"))?;
    let signature_input = parse_signature_input(&signature_input_header)
        .map_err(|err| http_signature_invalid(err.to_string()))?;
    let now = Utc::now();
    let now_unix_seconds = now.timestamp();
    validate_applet_signature_window(&signature_input, now_unix_seconds)?;
    let key_id_url = DidUrl::new(signature_input.key_id.clone()).map_err(|err| {
        http_signature_invalid(format!(
            "HTTP signature keyid `{}` is not a valid DID URL: {err}",
            signature_input.key_id
        ))
    })?;
    let signer_did = verification_method_did(&key_id_url).map_err(http_signature_invalid)?;
    if signer_did.as_str() != config.arkret.trusted_server_did {
        return Err(http_signature_invalid(
            "HTTP signature keyid is not owned by the trusted server DID",
        ));
    }

    let origin = header_value_from(headers, SOURCE_SERVICE_ID_HEADER)
        .ok_or_else(|| http_signature_invalid("Source-Service-ID header is required"))?;
    if origin != config.arkret.trusted_server_did {
        return Err(http_signature_invalid(
            "HTTP signature source service DID is not trusted",
        ));
    }

    let destination = header_value_from(headers, DESTINATION_SERVICE_ID_HEADER)
        .ok_or_else(|| http_signature_invalid("Destination-Service-ID header is required"))?;
    if destination != config.arkret.service_id {
        return Err(http_signature_invalid(
            "HTTP signature destination service DID does not match this bridge",
        ));
    }

    // The HTTP Message Signature is authenticated against the accepted
    // **source service** binding — the only purpose a bridge accepts. The
    // binding came from configuration at startup, so this is a pure in-memory
    // lookup, and a method with no acceptance fails closed instead of
    // triggering one.
    let accepted = bindings
        .source_service(&signer_did, &key_id_url, now)
        .map_err(|err| match err {
            BindingLookupError::Missing => {
                http_signature_invalid(format!("verification method {key_id_url} is not trusted"))
            }
            BindingLookupError::NotUsable { .. } => http_signature_invalid(format!(
                "source service verification method {key_id_url} is no longer accepted: {err}"
            )),
        })?;
    let public_key_bytes = public_key_material_from_binding(&accepted, &key_id_url)
        .map_err(|err| http_signature_invalid(err.to_string()))?
        .ed25519_bytes()
        .map_err(|err| http_signature_invalid(err.to_string()))?;
    let source_key_state_digest = arkret::canonical::canonical_digest(&public_key_bytes);
    let public_key = public_key_from_bytes(&public_key_bytes)
        .map_err(|err| http_signature_invalid(err.to_string()))?;
    let authority = request_authority(req, headers)?;
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let target_uri = request_target_uri(req, headers, &authority, &path);
    let mut required_components = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header(SOURCE_SERVICE_ID_HEADER.to_owned()),
        Component::Header(DESTINATION_SERVICE_ID_HEADER.to_owned()),
    ];
    if require_content_digest {
        required_components.push(Component::Header("content-digest".to_owned()));
        required_components.push(Component::Header("idempotency-key".to_owned()));
    }
    let policy = SignatureVerificationPolicy::new(required_components)
        .require_content_digest(require_content_digest)
        .max_clock_skew_seconds(APPLET_TRANSACTION_SIGNATURE_MAX_CLOCK_SKEW_SECS);
    let verified = verify_signed_http_message(
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
    let content_digest = verified
        .content_digest
        .as_ref()
        .map(|digest| digest.wire_value.clone());
    let covered_components = verified
        .signature_input
        .covered_components
        .iter()
        .map(Component::canonical_name)
        .collect();
    let canonical_message_digest = arkret::canonical::canonical_digest(&verified.canonical_message);
    let key_id = verified.signature_input.key_id.clone();
    let created = verified.signature_input.created;
    let expires = verified.signature_input.expires;
    Ok(VerifiedAppletHttpRequest {
        source_service_id: origin,
        destination_service_id: destination,
        key_id,
        source_key_state_digest,
        content_digest,
        covered_components,
        created,
        expires,
        canonical_message_digest,
    })
}

fn validate_applet_signature_window(
    signature_input: &SignatureInput,
    now_unix_seconds: i64,
) -> std::result::Result<(), HttpSignatureReject> {
    if signature_input.expires < signature_input.created {
        return Err(signature_window_invalid(
            "HTTP signature validity window is invalid",
        ));
    }
    if signature_input.expires - signature_input.created
        > APPLET_TRANSACTION_SIGNATURE_MAX_LIFETIME_SECS
    {
        return Err(signature_window_invalid(
            "HTTP signature validity window exceeds 300 seconds",
        ));
    }
    if signature_input.created
        < now_unix_seconds.saturating_sub(APPLET_TRANSACTION_SIGNATURE_MAX_CLOCK_SKEW_SECS)
        || signature_input.created
            > now_unix_seconds.saturating_add(APPLET_TRANSACTION_SIGNATURE_MAX_CLOCK_SKEW_SECS)
    {
        return Err(signature_window_invalid(
            "HTTP signature created timestamp is outside the accepted clock skew",
        ));
    }
    Ok(())
}

fn build_delivery_authentication_record_digest(
    verified: &VerifiedAppletHttpRequest,
    canonical_body_digest: &str,
    idempotency_key: &str,
) -> std::result::Result<String, String> {
    let content_digest = verified
        .content_digest
        .as_deref()
        .ok_or_else(|| "verified transaction missing Content-Digest".to_owned())?;
    arkret::canonical::canonical_sha256(&json!({
        "canonical_body_digest": canonical_body_digest,
        "canonical_message_digest": &verified.canonical_message_digest,
        "content_digest": content_digest,
        "covered_components": &verified.covered_components,
        "created": verified.created,
        "destination_service_id": &verified.destination_service_id,
        "direction": IdempotencyDirection::NodeToApplet.as_str(),
        "expires": verified.expires,
        "idempotency_key": idempotency_key,
        "operation_id": ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
        "source_key_state_digest": &verified.source_key_state_digest,
        "source_service_id": &verified.source_service_id,
        "verification_method": &verified.key_id,
    }))
    .map_err(|err| err.to_string())
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
    for event in &body.events {
        if event.proofs.is_empty() {
            return Err(format!("event {} has no proofs", event.event_id));
        }
        event
            .validate_proof_bindings()
            .map_err(|err| format!("event {} proof binding failed: {err}", event.event_id))?;
        let expected_signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
        let producer_proofs = event
            .proofs
            .iter()
            .filter_map(arkret_wire::EventProof::as_producer)
            .collect::<Vec<_>>();
        if producer_proofs.len() != 1 {
            return Err(format!(
                "event {} must carry exactly one producer proof",
                event.event_id
            ));
        }
        for proof in producer_proofs {
            proof.validate_production().map_err(|err| {
                format!("event {} proof is not production: {err}", event.event_id)
            })?;
            let signer_did = verification_method_did(&proof.verification_method)?;
            let signer_actor_id = arkret::project_full_id_to_core_id(&signer_did)
                .map_err(|error| error.to_string())?;
            if &signer_actor_id != expected_signer {
                return Err(format!(
                    "event {} proof signer DID does not match actor/executed_by",
                    event.event_id
                ));
            }
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
        let verification_method =
            DidUrl::new(method.verification_method.clone()).map_err(|err| {
                BridgeError::Config(format!(
                    "arkret.trusted_verification_methods[].verification_method \
                     `{}` is not a valid DID URL: {err}",
                    method.verification_method
                ))
            })?;
        // Normalize every accepted key form (raw / multibase / JWK) to the
        // multibase representation a DID document publishes, so the pinned
        // document is exactly what the SDK verifier expects to read back.
        let key_bytes = method.public_key.ed25519_bytes().map_err(|err| {
            BridgeError::Config(format!(
                "arkret.trusted_verification_methods[] key for `{verification_method}` \
                 is not a usable Ed25519 key: {err}"
            ))
        })?;
        authority
            .accept_configured_source_service_key(
                &verification_method,
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

/// Render the spec standard error response shape
/// (`{"ok":false,"error":{"code":..,"message":..}}`, see
/// `service-http-binding.md` §9) with a registry error code. The protocol
/// surface (`/_arkret/edge/applet/*`) is part of the universal failure surface
/// in `operations-error-mapping.json`, so the `code` must come from the closed
/// `error-code-registry.json` set rather than being a free-form string.
fn applet_error(res: &mut Response, status: StatusCode, code: &str, message: impl Into<String>) {
    res.status_code(status);
    res.render(Json(json!({
        "ok": false,
        "error": { "code": code, "message": message.into() },
    })));
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
    //! The inbound applet transaction path adds **zero** DID authority network
    //! calls, and now does so structurally: the runtime owns no resolver at
    //! all. What these tests pin is the split that replaced the old
    //! Event-signer resolution — the HTTP Message Signature is authenticated
    //! against the operator-configured `service` anchor, and Event proofs are
    //! only structurally validated, with signer authority carried by the source
    //! Arkret node that already completed admission.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret::signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};
    use arkret::{DidCoreId, DidFullId, Event, Hlc, RealmId, ScopeRef, TypedTrustDomainId};
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

    fn signer(seed: u8, actor: &DidFullId, verification_method: &DidUrl) -> Ed25519PayloadSigner {
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

    fn trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:bridge.example".to_owned()).expect("trust domain")
    }

    fn actor_did() -> DidFullId {
        DidFullId::new("did:webvh:z6mkfixture:alice.example".to_owned()).expect("actor did")
    }

    fn actor_verification_method() -> DidUrl {
        DidUrl::new(format!("{}#key-1", actor_did())).expect("did url")
    }

    fn actor_id(did: &DidFullId) -> DidCoreId {
        arkret::project_full_id_to_core_id(did).expect("actor core id")
    }

    fn server_did() -> DidFullId {
        DidFullId::new("did:webvh:z6mkfixture:server.example".to_owned()).expect("server did")
    }

    fn server_verification_method() -> DidUrl {
        DidUrl::new(format!("{}#tx-1", server_did())).expect("did url")
    }

    fn authority() -> DidAuthority {
        DidAuthority::new(trust_domain()).expect("authority")
    }

    /// One Event signed by `seed`'s key under `verification_method`.
    fn signed_event(actor: &DidFullId, verification_method: &DidUrl, seed: u8, seq: u64) -> Event {
        let realm =
            RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").expect("realm");
        let hlc = Hlc::new(format!("01970e589d2{seq}-0001-a13f9c2e")).expect("hlc");
        let mut event = arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id: realm },
            actor_id(actor),
            arkret::project_full_id_to_core_id(&server_did()).expect("server core id"),
            seq,
            hlc,
            json!({ "body": format!("hello {seq}") }),
        )
        .expect("event");
        sign_event(
            &mut event,
            &signer(seed, actor, verification_method),
            verification_method,
            SignEventOptions::new(),
        )
        .expect("sign event");
        event
    }

    fn transaction(events: Vec<Event>) -> AppletTransactionRequestBody {
        AppletTransactionRequestBody {
            source_service_id: arkret::project_full_id_to_core_id(&server_did())
                .expect("server core id"),
            events,
            signals: None,
        }
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
        let foreign =
            DidFullId::new("did:webvh:z6mkmallory:mallory.example".to_owned()).expect("did");
        let foreign_method = DidUrl::new(format!("{foreign}#key-1")).expect("did url");
        let mut event = signed_event(&foreign, &foreign_method, 42, 1);
        event.actor_id = actor_id(&actor_did());

        let err = verify_transaction_events(&transaction(vec![event]))
            .expect_err("signer/actor mismatch must be rejected");
        assert!(
            err.contains("proof binding failed") || err.contains("does not match"),
            "{err}"
        );
    }

    #[test]
    fn an_event_without_proofs_is_rejected() {
        let mut event = signed_event(&actor_did(), &actor_verification_method(), 42, 1);
        event.proofs.clear();
        let err = verify_transaction_events(&transaction(vec![event]))
            .expect_err("a proofless event must be rejected");
        assert!(err.contains("has no proofs"), "{err}");
    }

    #[test]
    fn an_empty_event_list_is_accepted() {
        verify_transaction_events(&transaction(Vec::new())).expect("empty transaction");
    }

    #[tokio::test]
    async fn a_malformed_event_proof_creates_no_idempotency_record() {
        let mut event = signed_event(&actor_did(), &actor_verification_method(), 42, 1);
        event.proofs.clear();
        let store = Arc::new(CountingIdempotencyStore::default());
        let replay = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            server_did().to_string(),
            "did:webvh:z6mkfixture:bridge.example",
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
}
