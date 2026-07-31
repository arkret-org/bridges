//! salvo HTTP service: health check / metrics / provisioning, plus mounting
//! the arkret applet routes (`/_arkret/edge/applet/*`) to receive event pushes
//! from the arkret server.

use std::sync::{Arc, OnceLock};

use ::metrics::{counter, describe_counter};
use arkret::identity::{public_key_material_from_binding, verify_event_proof_with_binding};
use arkret::signatures::EventProofBuilder;
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
use arkret_wire::DidUrl;
use chrono::{DateTime, Utc};
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
    // DID-P1-B01: the inbound path no longer carries a bare DID resolver. It
    // carries a `DidAuthority` (the only holder of a resolver, private field,
    // no accessor) plus the accepted-binding store the ordinary verification
    // path consumes. The trusted server's HTTP-signature keys are accepted from
    // configuration at startup, so authenticating an inbound push costs zero
    // network calls even on the very first request.
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
    source_signature_anchor: String,
) -> Result<TransactionClaim<AppletTransactionOutcome>> {
    run_blocking(move || store.claim(&replay, &hash, &source_signature_anchor)).await
}

async fn release_transaction_claim(
    store: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    replay: IdempotencyIdentity,
    hash: String,
    source_signature_anchor: String,
) -> Result<()> {
    run_blocking(move || store.release(&replay, &hash, &source_signature_anchor)).await
}

async fn record_transaction_outcome(
    store: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = BridgeError>>,
    replay: IdempotencyIdentity,
    hash: String,
    source_signature_anchor: String,
    response: AppletTransactionOutcome,
) -> Result<()> {
    run_blocking(move || store.record(&replay, &hash, &source_signature_anchor, &response)).await
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
    let source_signature_anchor =
        match build_source_signature_anchor(&verified, &request_hash, &idempotency_key) {
            Ok(anchor) => anchor,
            Err(err) => {
                record_applet_transaction("internal_error");
                internal_error(res, err);
                return;
            }
        };

    // §7.3: persist the idempotency claim before any side effect (the claim is
    // a durable `pending` record; the completed outcome replaces it below).
    match claim_transaction(
        state.idempotency.clone(),
        replay.clone(),
        request_hash.clone(),
        source_signature_anchor.clone(),
    )
    .await
    {
        Ok(TransactionClaim::Duplicate(response)) => {
            record_applet_transaction("duplicate");
            res.render(Json(response));
            return;
        }
        Ok(TransactionClaim::Pending) => {
            record_applet_transaction("pending");
            res.render(Json(arkret_models_integration::AppletTransactionOutcome {
                ok: false,
                rejected: Vec::new(),
                retry_after_ms: Some(1000),
            }));
            return;
        }
        Ok(TransactionClaim::Conflict) => {
            record_applet_transaction("conflict");
            // Same (source_service_id, Idempotency-Key) with a different body:
            // applet-integration §7.3/§14 require the closed error code
            // `duplicate_conflict` (the registry has no `idempotency_conflict`).
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(arkret_models_integration::AppletTransactionOutcome {
                ok: false,
                rejected: vec![RejectedItem {
                    event_id: None,
                    reason_code: "duplicate_conflict".to_owned(),
                    retry_after_ms: None,
                }],
                retry_after_ms: None,
            }));
            return;
        }
        Ok(TransactionClaim::Claimed) => {}
        Err(err) => {
            record_applet_transaction("internal_error");
            internal_error(res, err.to_string());
            return;
        }
    }

    let did_authority = state.did_authority.clone();
    let body_for_verification = body.clone();
    let verification_result = run_blocking(move || {
        Ok(authenticate_transaction_events(
            did_authority.as_ref(),
            &body_for_verification,
            Utc::now(),
        ))
    })
    .await;
    match verification_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            if let Err(release_err) = release_transaction_claim(
                state.idempotency.clone(),
                replay.clone(),
                request_hash.clone(),
                source_signature_anchor.clone(),
            )
            .await
            {
                tracing::warn!(error = %release_err, "failed to release idempotency claim");
            }
            record_applet_transaction("unauthorized");
            unauthorized(res, err);
            return;
        }
        Err(err) => {
            if let Err(release_err) = release_transaction_claim(
                state.idempotency.clone(),
                replay.clone(),
                request_hash.clone(),
                source_signature_anchor.clone(),
            )
            .await
            {
                tracing::warn!(error = %release_err, "failed to release idempotency claim");
            }
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
                source_signature_anchor,
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
                source_signature_anchor,
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

    // DID-P1-B01: the HTTP Message Signature is authenticated against the
    // accepted **source service** binding, never against an Event-signer
    // binding — the two live under different `DidBindingPurpose`s, so the store
    // key alone makes substitution impossible. The binding was accepted from
    // configuration at startup, so this is a pure in-memory lookup.
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

fn build_source_signature_anchor(
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
        "operation_id": arkret::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
        "source_key_state_digest": &verified.source_key_state_digest,
        "source_service_id": &verified.source_service_id,
        "verification_method": &verified.key_id,
    }))
    .map_err(|err| err.to_string())
}

/// Outcome of one zero-network verification pass over a transaction's Events.
#[derive(Debug, PartialEq, Eq)]
enum EventProofVerification {
    /// Every proof verified against an already-accepted binding.
    Verified,
    /// Every structural check passed, but these `verification_method`s have no
    /// accepted binding in this trust domain yet. This is the *only* condition
    /// that may enter the §4 authority path — and only rows 1 / 3 of the closed
    /// trigger table ("此前未被本 trust domain 接受的 DID 首次跨越信任边界" /
    /// "出现新的 verification_method").
    NeedsAuthority(Vec<DidUrl>),
}

/// Authenticate every Event proof in a pushed transaction.
///
/// Two clearly separated counters (`did-usage-and-verification.md` §6):
///
/// - **signature verifications** grow with the number of proofs, always;
/// - **authority network calls** grow only with *newly seen* signer keys.
///
/// A warm transaction — same signer keys as the previous one — runs exactly one
/// [`verify_transaction_events`] pass and makes **zero** resolver calls.
fn authenticate_transaction_events(
    authority: &DidAuthority,
    body: &AppletTransactionRequestBody,
    now: DateTime<Utc>,
) -> std::result::Result<(), String> {
    match verify_transaction_events(authority.bindings(), body, now)? {
        EventProofVerification::Verified => return Ok(()),
        EventProofVerification::NeedsAuthority(verification_methods) => {
            // §4 rows 1/3. Each miss costs exactly one resolution; the
            // acceptance is then reusable for every later transaction under the
            // same DID / trust domain / purpose / policy digest.
            for verification_method in &verification_methods {
                authority.accept_event_signer(verification_method, now)?;
            }
        }
    }
    match verify_transaction_events(authority.bindings(), body, now)? {
        EventProofVerification::Verified => Ok(()),
        // Fail closed: §4 forbids a "resolve once more to be safe" retry loop.
        EventProofVerification::NeedsAuthority(verification_methods) => Err(format!(
            "event proof signer keys are still unaccepted after DID authority verification: {}",
            verification_methods
                .iter()
                .map(DidUrl::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Verify every Event proof against **accepted DID bindings only**.
///
/// Zero network calls by construction: [`AcceptedDidBindings`] holds a binding
/// store and nothing else, so this function has no resolver to call. That is the
/// §6 requirement ("业务 reducer / query 只消费 verified binding … 不直接持有
/// 通用网络 resolver") enforced by the type system rather than by review.
///
/// The proof's key comes from the DID document the binding pinned at acceptance
/// time. Everything else — the §6 `event_digest` binding, the canonical proof
/// binding object and the detached JWS itself — is still verified in full for
/// every proof (§3: "普通签名对象仍 MUST 验证签名、canonical transcript …").
fn verify_transaction_events(
    bindings: &AcceptedDidBindings,
    body: &AppletTransactionRequestBody,
    now: DateTime<Utc>,
) -> std::result::Result<EventProofVerification, String> {
    let builder = EventProofBuilder::new();
    let mut unaccepted: Vec<DidUrl> = Vec::new();
    for event in &body.events {
        if event.proofs.is_empty() {
            return Err(format!("event {} has no proofs", event.event_id));
        }
        event
            .validate_proof_bindings()
            .map_err(|err| format!("event {} proof binding failed: {err}", event.event_id))?;
        let canonical_bytes = builder
            .envelope_bytes(event)
            .map_err(|err| format!("event {} canonicalization failed: {err}", event.event_id))?;
        let expected_signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
        for proof in &event.proofs {
            proof.validate_production().map_err(|err| {
                format!("event {} proof is not production: {err}", event.event_id)
            })?;
            let signer_did = verification_method_did(&proof.verification_method)?;
            if &signer_did != expected_signer {
                return Err(format!(
                    "event {} proof signer DID does not match actor/executed_by",
                    event.event_id
                ));
            }
            let accepted = match bindings.event_signer(&signer_did, &proof.verification_method, now)
            {
                Ok(accepted) => accepted,
                Err(BindingLookupError::Missing) => {
                    if !unaccepted.contains(&proof.verification_method) {
                        unaccepted.push(proof.verification_method.clone());
                    }
                    continue;
                }
                // `deactivated` / `quarantined` is a decision, not a gap: it
                // MUST NOT be "repaired" by resolving again (§5).
                Err(err @ BindingLookupError::NotUsable { .. }) => {
                    return Err(format!(
                        "event {} proof signer `{}` rejected: {err}",
                        event.event_id, proof.verification_method
                    ));
                }
            };
            // The SDK's Event-proof entry point: it keeps the Event profile
            // (`DetachedJwsProtectedHeader`, which rejects a `kid` member and
            // requires `header.alg == proof.alg`) and additionally re-checks the
            // binding status, the method↔issuer relation and that the pinned
            // document still hashes to the binding's `document_digest`. Routing
            // this through the generic JWS path would verify the wrong bytes and
            // relax two header checks.
            verify_event_proof_with_binding(proof, &canonical_bytes, &event.actor_id, &accepted)
                .map_err(|err| {
                    format!("event {} proof verification failed: {err}", event.event_id)
                })?;
        }
    }
    if unaccepted.is_empty() {
        Ok(EventProofVerification::Verified)
    } else {
        Ok(EventProofVerification::NeedsAuthority(unaccepted))
    }
}

/// Accept the operator-configured HTTP Message Signature trust anchors as
/// `service`-purpose bindings, once, at startup.
///
/// These are the *source service* keys of the pushing Arkret node. They are a
/// completely separate acceptance from the Event-signer bindings above: a
/// different [`arkret::identity::DidBindingPurpose`] means a different store
/// key, so neither can ever stand in for the other even when the DIDs coincide
/// (DID-P1-B01).
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
    applet_error(res, StatusCode::BAD_REQUEST, "bad_json", message);
}

fn unauthorized(res: &mut Response, message: impl Into<String>) {
    applet_error(res, StatusCode::UNAUTHORIZED, "invalid_signature", message);
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
    //! DID-P1-B02 acceptance: the inbound applet transaction path verifies
    //! every signature it is given while adding **zero** DID authority network
    //! calls once the bindings are accepted
    //! (`did-usage-and-verification.md` §6, last bullet).
    //!
    //! Every test here drives [`DidAuthority`] with a `CountingDidResolver`, so
    //! `resolver.calls()` is the literal `authority_network_call_count` of the
    //! task's acceptance criteria; `signature_verify_count` is the number of
    //! Event proofs the assertions walk through.

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret::identity::{DidDocument, DidResolver, IdentityError};
    use arkret::signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};
    use arkret::{Did, Event, Hlc, RealmId, ScopeRef, TypedTrustDomainId};

    use super::*;

    // ========================================================================
    // Counting resolver spy (mirrors the SDK's
    // `crates/identity/tests/binding_resolver_spy.rs`)
    // ========================================================================

    /// Serves DID documents from an in-memory table and counts every
    /// resolution. A local binding-store lookup or a per-signature verification
    /// must never reach this type at all.
    #[derive(Debug, Default)]
    struct CountingDidResolver {
        documents: std::sync::Mutex<BTreeMap<String, DidDocument>>,
        calls: AtomicUsize,
    }

    impl CountingDidResolver {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn publish(&self, did: &Did, verification_method: &DidUrl, seed: u8) {
            let multibase = arkret::ed25519_pubkey_to_did_key_multibase(&public_key_bytes(seed));
            self.documents.lock().expect("lock").insert(
                did.as_str().to_owned(),
                DidDocument::new(
                    did.clone(),
                    verification_method.as_str().to_owned(),
                    multibase,
                ),
            );
        }
    }

    impl DidResolver for CountingDidResolver {
        fn supports(&self, _did: &Did) -> bool {
            true
        }

        fn resolve_did(
            &self,
            did: &Did,
        ) -> std::result::Result<arkret::identity::ResolvedDid, IdentityError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.documents
                .lock()
                .expect("lock")
                .get(did.as_str())
                .cloned()
                // Plain HTTP `did:webvh` documents publish no method evidence,
                // so the spy mirrors the production chain: proofless.
                .map(arkret::identity::ResolvedDid::proofless)
                .ok_or_else(|| IdentityError::Protocol(format!("unknown DID `{did}`")))
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

    fn trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:bridge.example".to_owned()).expect("trust domain")
    }

    fn actor_did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).expect("actor did")
    }

    fn actor_verification_method() -> DidUrl {
        DidUrl::new(format!("{}#key-1", actor_did())).expect("did url")
    }

    fn server_did() -> Did {
        Did::new("did:webvh:z6mkfixture:server.example".to_owned()).expect("server did")
    }

    fn server_verification_method() -> DidUrl {
        DidUrl::new(format!("{}#tx-1", server_did())).expect("did url")
    }

    fn authority_with(resolver: Arc<CountingDidResolver>) -> DidAuthority {
        DidAuthority::with_resolver(trust_domain(), resolver).expect("authority")
    }

    /// One Event signed by `seed`'s key under `verification_method`.
    fn signed_event(actor: &Did, verification_method: &DidUrl, seed: u8, seq: u64) -> Event {
        let realm = RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").expect("realm");
        let hlc = Hlc::new(format!("01970e589d2{seq}-0001-a13f9c2e")).expect("hlc");
        let mut event = Event::new(
            "ak.message.create",
            ScopeRef::Realm { realm_id: realm },
            actor.clone(),
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
            source_service_id: server_did(),
            events,
            signals: None,
        }
    }

    fn seed_source_service(authority: &DidAuthority, seed: u8, now: DateTime<Utc>) {
        let key_bytes = public_key_bytes(seed);
        authority
            .accept_configured_source_service_key(
                &server_verification_method(),
                &arkret::ed25519_pubkey_to_did_key_multibase(&key_bytes),
                now,
            )
            .expect("source service binding");
    }

    // ========================================================================
    // B02 #1 — two transactions in the same epoch: every proof verified,
    // resolver network delta 0.
    // ========================================================================

    #[test]
    fn two_transactions_under_the_same_bindings_add_zero_authority_calls() {
        let resolver = Arc::new(CountingDidResolver::default());
        resolver.publish(&actor_did(), &actor_verification_method(), 42);
        let authority = authority_with(resolver.clone());
        let now = Utc::now();
        // The HTTP Message Signature anchor is accepted from configuration, so
        // it never costs a resolution at all.
        seed_source_service(&authority, 7, now);
        assert_eq!(resolver.calls(), 0);

        // First transaction: the actor's key is new to this trust domain, which
        // is §4 trigger row 1 — exactly one resolution.
        let first = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            42,
            1,
        )]);
        authenticate_transaction_events(&authority, &first, now).expect("first transaction");
        assert_eq!(resolver.calls(), 1);

        // Second transaction in the same epoch: both Events verify, zero new
        // authority calls.
        let second = transaction(vec![
            signed_event(&actor_did(), &actor_verification_method(), 42, 2),
            signed_event(&actor_did(), &actor_verification_method(), 42, 3),
        ]);
        authenticate_transaction_events(&authority, &second, now).expect("second transaction");
        assert_eq!(
            resolver.calls(),
            1,
            "an ordinary transaction must not add a DID authority network call"
        );

        // The HTTP signature key is still served from the accepted source
        // service binding, also with zero resolutions.
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
        assert_eq!(resolver.calls(), 1);
    }

    // ========================================================================
    // B02 #2 — unknown Event signer: positive and negative.
    // ========================================================================

    #[test]
    fn an_unknown_event_signer_that_resolves_is_accepted_exactly_once() {
        let resolver = Arc::new(CountingDidResolver::default());
        resolver.publish(&actor_did(), &actor_verification_method(), 42);
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        let body = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            42,
            1,
        )]);
        assert_eq!(
            verify_transaction_events(authority.bindings(), &body, now).expect("pass"),
            EventProofVerification::NeedsAuthority(vec![actor_verification_method()]),
            "the ordinary path must report the gap, not resolve it itself"
        );
        assert_eq!(resolver.calls(), 0);

        authenticate_transaction_events(&authority, &body, now).expect("accepted");
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn an_unknown_event_signer_that_cannot_be_resolved_fails_closed() {
        let resolver = Arc::new(CountingDidResolver::default());
        // Nothing published: the DID does not exist for this bridge.
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        let body = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            42,
            1,
        )]);
        let err = authenticate_transaction_events(&authority, &body, now)
            .expect_err("unknown signer must fail closed");
        assert!(err.contains("DID authority verification failed"), "{err}");
        assert_eq!(
            resolver.calls(),
            1,
            "a failure must not turn into a retry loop"
        );
    }

    #[test]
    fn an_event_proof_signed_by_a_key_the_document_does_not_publish_is_rejected() {
        let resolver = Arc::new(CountingDidResolver::default());
        // The document publishes seed 42's key; the Event is signed with 43.
        resolver.publish(&actor_did(), &actor_verification_method(), 42);
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        let body = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            43,
            1,
        )]);
        let err = authenticate_transaction_events(&authority, &body, now)
            .expect_err("wrong key must be rejected");
        assert!(err.contains("proof verification failed"), "{err}");
    }

    #[test]
    fn an_event_proof_signed_by_a_foreign_did_is_rejected_before_any_resolution() {
        let resolver = Arc::new(CountingDidResolver::default());
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        // The Event's `actor_id` and the proof's verification method disagree.
        let foreign = Did::new("did:webvh:z6mkfixture:mallory.example".to_owned()).expect("did");
        let foreign_method = DidUrl::new(format!("{foreign}#key-1")).expect("did url");
        let mut event = signed_event(&foreign, &foreign_method, 42, 1);
        event.actor_id = actor_did();

        let err = authenticate_transaction_events(&authority, &transaction(vec![event]), now)
            .expect_err("signer/actor mismatch must be rejected");
        assert!(
            err.contains("proof binding failed") || err.contains("does not match"),
            "{err}"
        );
        assert_eq!(
            resolver.calls(),
            0,
            "structural rejection must never reach the resolver"
        );
    }

    // ========================================================================
    // B01 — the two binding purposes may not substitute for each other.
    // ========================================================================

    #[test]
    fn a_source_service_binding_cannot_authenticate_an_event_proof() {
        let resolver = Arc::new(CountingDidResolver::default());
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        // Accept the actor's very key as a *source service* anchor.
        let key_bytes = public_key_bytes(42);
        authority
            .accept_configured_source_service_key(
                &actor_verification_method(),
                &arkret::ed25519_pubkey_to_did_key_multibase(&key_bytes),
                now,
            )
            .expect("service binding");

        // The Event proof path still sees no binding: `service` cannot stand in
        // for the Event signer purpose.
        let body = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            42,
            1,
        )]);
        assert_eq!(
            verify_transaction_events(authority.bindings(), &body, now).expect("pass"),
            EventProofVerification::NeedsAuthority(vec![actor_verification_method()])
        );
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn an_event_signer_binding_cannot_authenticate_the_http_signature() {
        let resolver = Arc::new(CountingDidResolver::default());
        resolver.publish(&server_did(), &server_verification_method(), 7);
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        // Accept the *node's* key, but only for the Event signer purpose.
        authority
            .accept_event_signer(&server_verification_method(), now)
            .expect("event signer binding");
        assert_eq!(resolver.calls(), 1);

        // The HTTP Message Signature lookup is keyed by `service` and misses.
        assert_eq!(
            authority
                .bindings()
                .source_service(&server_did(), &server_verification_method(), now),
            Err(BindingLookupError::Missing)
        );
        assert_eq!(resolver.calls(), 1);
    }

    // ========================================================================
    // B02 #2 — source service key rotation and epoch renewal.
    // ========================================================================

    #[test]
    fn rotating_the_source_service_key_replaces_the_http_signature_material() {
        let resolver = Arc::new(CountingDidResolver::default());
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        seed_source_service(&authority, 7, now);
        let before = authority
            .bindings()
            .source_service(&server_did(), &server_verification_method(), now)
            .expect("binding");
        assert_eq!(
            public_key_material_from_binding(&before, &server_verification_method())
                .expect("material")
                .ed25519_bytes()
                .expect("bytes"),
            public_key_bytes(7)
        );

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
        assert_eq!(
            resolver.calls(),
            0,
            "a configured anchor rotation never touches the network"
        );
    }

    #[test]
    fn invalidating_an_event_signer_triggers_exactly_one_new_authority_call() {
        let resolver = Arc::new(CountingDidResolver::default());
        resolver.publish(&actor_did(), &actor_verification_method(), 42);
        let authority = authority_with(resolver.clone());
        let now = Utc::now();

        let first = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            42,
            1,
        )]);
        authenticate_transaction_events(&authority, &first, now).expect("first");
        assert_eq!(resolver.calls(), 1);

        // Epoch renewal / rotation: the actor re-keys under the same
        // verification method id.
        resolver.publish(&actor_did(), &actor_verification_method(), 43);
        let rotated = transaction(vec![signed_event(
            &actor_did(),
            &actor_verification_method(),
            43,
            2,
        )]);
        // Without an invalidation the pinned binding is used and the new
        // signature fails closed — the ordinary path never "resolves once more
        // to be safe".
        let err = authenticate_transaction_events(&authority, &rotated, now)
            .expect_err("stale key must fail closed");
        assert!(err.contains("proof verification failed"), "{err}");
        assert_eq!(resolver.calls(), 1);

        assert_eq!(authority.invalidate_did(&actor_did()), 1);
        authenticate_transaction_events(&authority, &rotated, now).expect("after invalidation");
        assert_eq!(
            resolver.calls(),
            2,
            "invalidation must cost exactly one refresh"
        );
    }

    #[test]
    fn an_empty_event_list_is_authenticated_without_touching_the_resolver() {
        let resolver = Arc::new(CountingDidResolver::default());
        let authority = authority_with(resolver.clone());
        authenticate_transaction_events(&authority, &transaction(Vec::new()), Utc::now())
            .expect("empty transaction");
        assert_eq!(resolver.calls(), 0);
    }
}
