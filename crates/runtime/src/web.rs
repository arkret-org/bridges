//! salvo HTTP service: health check / metrics / provisioning, plus mounting
//! the arkret applet routes (`/_arkret/edge/applet/*`) to receive event pushes
//! from the arkret server.

use std::sync::{Arc, OnceLock};

use ::metrics::{counter, describe_counter};
use arkret::identity::{ResolverFailMode, ResolverPolicy};
use arkret::models::{AppletTransactionOutcome, AppletTransactionRequestBody};
use arkret::signatures::http_signature::{
    Component, HttpMessageVerificationError, SignatureInput, SignaturePolicyError,
    SignatureVerificationPolicy, parse_signature_input, public_key_from_bytes,
    verify_signed_http_message,
};
use arkret::signatures::{EventProofBuilder, PublicKeyMaterial, verify_eddsa_detached_jws_proof};
use arkret::{
    AppletHandler, CompositeDidResolver, Did, DidKeyResolver, DidResolver, HttpDidResolver,
    RejectedItem,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use salvo::affix_state;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::app::BridgeContext;
use crate::arkret_edge::BridgeAppletHandler;
use crate::config::{Config, TrustedVerificationMethodConfig};
use crate::db::{DbEventDedupStore, DbTransactionIdempotencyStore};
use crate::error::{BridgeError, Result};
use crate::idempotency::{
    EventDedupStore, TransactionClaim, TransactionIdempotencyStore, TransactionReplayKey,
};
use crate::run_blocking;

static PROMETHEUS_HANDLE: OnceLock<std::result::Result<PrometheusHandle, String>> = OnceLock::new();
const APPLET_TRANSACTION_DIRECTION: &str = "node_to_applet";
const APPLET_TRANSACTION_SIGNATURE_MAX_LIFETIME_SECS: i64 = 300;
const APPLET_TRANSACTION_SIGNATURE_MAX_CLOCK_SKEW_SECS: i64 = 30;
/// Upper bound on the inbound edge `transactions` body, mirroring the webhook
/// surface's `MAX_WEBHOOK_BODY_BYTES` (1 MiB). Without it the body is buffered
/// into memory in full *before* signature verification, an unauthenticated
/// memory-pressure vector on any deployment that exposes this surface.
const MAX_APPLET_TRANSACTION_BODY_BYTES: usize = 1024 * 1024;
const SOURCE_SERVICE_ID_HEADER: &str = "source-service-id";
const DESTINATION_SERVICE_ID_HEADER: &str = "destination-service-id";

#[derive(Clone)]
struct OwnedTransactionReplayKey {
    source_service_id: String,
    destination_service_id: String,
    idempotency_key: String,
}

impl OwnedTransactionReplayKey {
    fn as_replay(&self) -> TransactionReplayKey<'_> {
        TransactionReplayKey {
            operation_id: arkret::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
            direction: APPLET_TRANSACTION_DIRECTION,
            source_service_id: &self.source_service_id,
            destination_service_id: &self.destination_service_id,
            idempotency_key: &self.idempotency_key,
        }
    }
}

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
    let idempotency: Arc<dyn TransactionIdempotencyStore> =
        Arc::new(DbTransactionIdempotencyStore::new(ctx.db.clone())?);
    // The trust-root DID resolver authenticates the inbound source service DID
    // signature and every pushed Event proof. The same resolver is shared with
    // the applet handler so its `source_did_resolver()` (SDK AppletHandler
    // contract) and the per-event proof verification trust the same roots.
    let event_proof_resolver = Arc::new(build_event_proof_resolver()?);
    let handler = Arc::new(BridgeAppletHandler::new(
        &ctx.edge,
        ctx.resolver(),
        dedup,
        ctx.handled_event_kinds(),
        event_proof_resolver.clone(),
    )?);
    let applet = applet_router(AppletWebState {
        handler,
        config: ctx.config.clone(),
        idempotency,
        event_proof_resolver,
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
        describe_counter!(
            crate::metrics::BRIDGE_MESSAGES_METRIC,
            "App<->arkret bridged message count, labelled by bridge, direction (inbound/outbound/inbound_media) and result (ok/error)."
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
    idempotency: Arc<dyn TransactionIdempotencyStore>,
    event_proof_resolver: Arc<CompositeDidResolver>,
}

async fn claim_transaction(
    store: Arc<dyn TransactionIdempotencyStore>,
    replay: OwnedTransactionReplayKey,
    hash: String,
    source_signature_anchor: String,
) -> Result<TransactionClaim> {
    run_blocking(move || {
        let replay = replay.as_replay();
        store.claim(&replay, &hash, &source_signature_anchor)
    })
    .await
}

async fn release_transaction_claim(
    store: Arc<dyn TransactionIdempotencyStore>,
    replay: OwnedTransactionReplayKey,
    hash: String,
    source_signature_anchor: String,
) -> Result<()> {
    run_blocking(move || {
        let replay = replay.as_replay();
        store.release(&replay, &hash, &source_signature_anchor)
    })
    .await
}

async fn record_transaction_outcome(
    store: Arc<dyn TransactionIdempotencyStore>,
    replay: OwnedTransactionReplayKey,
    hash: String,
    source_signature_anchor: String,
    response: AppletTransactionOutcome,
) -> Result<()> {
    run_blocking(move || {
        let replay = replay.as_replay();
        store.record(&replay, &hash, &source_signature_anchor, &response)
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
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
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
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
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

    let verified = match verify_http_transaction_request(req, &headers, &body_bytes, &state.config)
    {
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
    let replay = OwnedTransactionReplayKey {
        source_service_id: source.clone(),
        destination_service_id: destination,
        idempotency_key: idempotency_key.clone(),
    };
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
            res.render(Json(arkret::models::AppletTransactionOutcome {
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
            res.render(Json(arkret::models::AppletTransactionOutcome {
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

    let event_proof_resolver = state.event_proof_resolver.clone();
    let body_for_verification = body.clone();
    let verification_result = run_blocking(move || {
        Ok(verify_transaction_events(
            event_proof_resolver.as_ref(),
            &body_for_verification,
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
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
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
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
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
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
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
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
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
) -> std::result::Result<VerifiedAppletHttpRequest, HttpSignatureReject> {
    verify_http_applet_request(req, headers, body, config, true)
}

fn verify_http_applet_get_request(
    req: &Request,
    config: &Config,
) -> std::result::Result<(), HttpSignatureReject> {
    let headers = collect_headers(req);
    verify_http_applet_request(req, &headers, &[], config, false).map(|_| ())
}

fn verify_http_applet_request(
    req: &Request,
    headers: &[(String, String)],
    body: &[u8],
    config: &Config,
    require_content_digest: bool,
) -> std::result::Result<VerifiedAppletHttpRequest, HttpSignatureReject> {
    let signature_input_header = header_value_from(headers, "signature-input")
        .ok_or_else(|| http_signature_required("Signature-Input header is required"))?;
    let signature_input = parse_signature_input(&signature_input_header)
        .map_err(|err| http_signature_invalid(err.to_string()))?;
    let now_unix_seconds = chrono::Utc::now().timestamp();
    validate_applet_signature_window(&signature_input, now_unix_seconds)?;
    let trusted_method = trusted_verification_method(config, &signature_input.key_id)?;
    let signer_did =
        verification_method_did(&signature_input.key_id).map_err(http_signature_invalid)?;
    if signer_did != config.arkret.trusted_server_did {
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

    let public_key_bytes = trusted_method
        .public_key
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
        "direction": APPLET_TRANSACTION_DIRECTION,
        "expires": verified.expires,
        "idempotency_key": idempotency_key,
        "operation_id": arkret::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
        "source_key_state_digest": &verified.source_key_state_digest,
        "source_service_id": &verified.source_service_id,
        "verification_method": &verified.key_id,
    }))
    .map_err(|err| err.to_string())
}

fn verify_transaction_events(
    resolver: &CompositeDidResolver,
    body: &AppletTransactionRequestBody,
) -> std::result::Result<(), String> {
    let builder = EventProofBuilder::new();
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
        let expected_signer = event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .to_string();
        for proof in &event.proofs {
            proof.validate_production().map_err(|err| {
                format!("event {} proof is not production: {err}", event.event_id)
            })?;
            let signer_did = verification_method_did(&proof.verification_method)?;
            if signer_did != expected_signer {
                return Err(format!(
                    "event {} proof signer DID does not match actor/executed_by",
                    event.event_id
                ));
            }
            let public_key = resolve_verification_method_key(resolver, &proof.verification_method)?;
            verify_eddsa_detached_jws_proof(proof, &canonical_bytes, &event.actor_id, &public_key)
                .map_err(|err| {
                    format!("event {} proof verification failed: {err}", event.event_id)
                })?;
        }
    }
    Ok(())
}

fn build_event_proof_resolver() -> Result<CompositeDidResolver> {
    let policy = ResolverPolicy {
        // Workspace-wide rule: actor/service identities are did:webvh only
        // (did:web is not an accepted alias). did:key stays for bare
        // verification-method keys.
        allowed_methods: vec!["did:key:".to_owned(), "did:webvh:".to_owned()],
        fail_mode: ResolverFailMode::FailClosed,
        ..ResolverPolicy::default()
    };
    let mut resolver = CompositeDidResolver::new().with_policy(policy.clone());
    resolver.push(DidKeyResolver::new());
    resolver.push(HttpDidResolver::with_policy(policy)?);
    Ok(resolver)
}

fn resolve_verification_method_key(
    resolver: &CompositeDidResolver,
    verification_method: &str,
) -> std::result::Result<PublicKeyMaterial, String> {
    let signer_did = verification_method_did(verification_method)?;
    let did = Did::new(signer_did.clone())
        .map_err(|err| format!("verification method DID `{signer_did}` is invalid: {err}"))?;
    let document = resolver
        .resolve_did(&did)
        .map_err(|err| format!("DID resolution failed for `{signer_did}`: {err}"))?;
    if document.id != did {
        return Err(format!(
            "DID document id `{}` does not match requested `{signer_did}`",
            document.id
        ));
    }
    let key_value = verification_method_value(&document.verification_methods, verification_method)
        .ok_or_else(|| {
            format!(
                "verification method `{verification_method}` not found in DID document `{signer_did}`"
            )
        })?;
    public_key_material_from_did_document_value(key_value)
}

fn verification_method_value<'a>(
    verification_methods: &'a std::collections::BTreeMap<String, String>,
    verification_method: &str,
) -> Option<&'a str> {
    let fragment = verification_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment);
    let allow_single_key_fallback = verification_method.starts_with("did:key:");
    verification_methods
        .get(verification_method)
        .or_else(|| fragment.and_then(|fragment| verification_methods.get(fragment)))
        .or_else(|| fragment.and_then(|fragment| verification_methods.get(&format!("#{fragment}"))))
        .or_else(|| {
            if allow_single_key_fallback && verification_methods.len() == 1 {
                verification_methods.values().next()
            } else {
                None
            }
        })
        .map(String::as_str)
}

fn public_key_material_from_did_document_value(
    value: &str,
) -> std::result::Result<PublicKeyMaterial, String> {
    let value = value.trim();
    if let Some(multibase) = value.strip_prefix("did:key:") {
        let multibase = multibase
            .rsplit_once('#')
            .map(|(_, fragment)| fragment)
            .unwrap_or(multibase);
        return Ok(PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        });
    }
    if value.starts_with('z') {
        return Ok(PublicKeyMaterial::Ed25519Multibase {
            value: value.to_owned(),
        });
    }
    let parsed: Value = serde_json::from_str(value)
        .map_err(|err| format!("DID verification method key is not multibase or JSON: {err}"))?;
    if let Some(multibase) = parsed.get("publicKeyMultibase").and_then(Value::as_str) {
        return Ok(PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        });
    }
    if let Some(jwk) = parsed.get("publicKeyJwk") {
        return Ok(PublicKeyMaterial::Jwk { value: jwk.clone() });
    }
    if parsed.get("kty").is_some() && parsed.get("crv").is_some() && parsed.get("x").is_some() {
        return Ok(PublicKeyMaterial::Jwk { value: parsed });
    }
    Err("DID verification method does not expose publicKeyMultibase or publicKeyJwk".to_owned())
}

fn trusted_verification_method<'a>(
    config: &'a Config,
    verification_method: &str,
) -> std::result::Result<&'a TrustedVerificationMethodConfig, HttpSignatureReject> {
    config
        .arkret
        .trusted_verification_methods
        .iter()
        .find(|method| method.verification_method == verification_method)
        .ok_or_else(|| {
            http_signature_invalid(format!(
                "verification method {verification_method} is not trusted"
            ))
        })
}

fn verification_method_did(verification_method: &str) -> std::result::Result<String, String> {
    verification_method
        .rsplit_once('#')
        .map(|(did, _)| did.to_owned())
        .filter(|did| !did.is_empty())
        .ok_or_else(|| format!("verification method {verification_method} has no DID fragment"))
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
        HttpMessageVerificationError::Policy(_) | HttpMessageVerificationError::Signature(_) => {
            http_signature_invalid(message)
        }
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
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn verification_method_lookup_accepts_full_fragment_and_single_key_documents() {
        let key = arkret::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]);

        let mut full = BTreeMap::new();
        full.insert("did:webvh:server.example#key-1".to_owned(), key.clone());
        assert_eq!(
            verification_method_value(&full, "did:webvh:server.example#key-1"),
            Some(key.as_str())
        );

        let mut fragment = BTreeMap::new();
        fragment.insert("#key-1".to_owned(), key.clone());
        assert_eq!(
            verification_method_value(&fragment, "did:webvh:server.example#key-1"),
            Some(key.as_str())
        );

        let mut single_did_key = BTreeMap::new();
        single_did_key.insert("unexpected-key-id".to_owned(), key.clone());
        let did_key_method = format!("did:key:{key}#{key}");
        assert_eq!(
            verification_method_value(&single_did_key, &did_key_method),
            Some(key.as_str())
        );

        let mut mismatched_webvh = BTreeMap::new();
        mismatched_webvh.insert("unexpected-key-id".to_owned(), key);
        assert_eq!(
            verification_method_value(&mismatched_webvh, "did:webvh:server.example#key-1"),
            None
        );
    }

    #[test]
    fn did_document_key_material_accepts_multibase_did_key_and_jwk_container() {
        let multibase = arkret::ed25519_pubkey_to_did_key_multibase(&[8u8; 32]);
        let public_key =
            public_key_material_from_did_document_value(&format!("did:key:{multibase}")).unwrap();
        assert_eq!(public_key.ed25519_bytes().unwrap(), [8u8; 32]);

        let jwk = serde_json::json!({
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": arkret::base64url_encode([9u8; 32]),
            }
        });
        let public_key = public_key_material_from_did_document_value(&jwk.to_string()).unwrap();
        assert_eq!(public_key.ed25519_bytes().unwrap(), [9u8; 32]);
    }
}
