//! salvo HTTP service: health check / metrics / provisioning, plus mounting
//! the cokret applet routes (`/_cokret/edge/applet/*`) to receive event pushes
//! from the cokret server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cokret::identity::{ResolverFailMode, ResolverPolicy};
use cokret::model::{AppletTransactionOutcome, AppletTransactionRequestBody};
use cokret::signatures::http_signature::{
    Component, SignatureVerificationPolicy, parse_signature_input, public_key_from_bytes,
    verify_signed_http_message,
};
use cokret::signatures::{Ed25519DetachedJwsVerifier, EventProofBuilder, PublicKeyMaterial};
use cokret::{
    AppletHandler, CompositeDidResolver, Did, DidKeyResolver, DidResolver, HttpDidResolver,
};
use parking_lot::Mutex;
use salvo::{affix_state, http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::app::BridgeContext;
use crate::cokret_edge::BridgeAppletHandler;
use crate::config::{Config, TrustedVerificationMethodConfig};
use crate::error::{BridgeError, Result};

/// Start the web service and run it blocking. `extra` is each app adapter's
/// webhook routes (optional).
pub async fn serve(ctx: Arc<BridgeContext>, extra: Option<Router>) -> Result<()> {
    let handler = Arc::new(BridgeAppletHandler::new(&ctx.edge, ctx.resolver()));
    let event_proof_resolver = Arc::new(build_event_proof_resolver()?);
    let applet = applet_router(AppletWebState {
        handler,
        config: ctx.config.clone(),
        idempotency: Arc::new(TransactionIdempotencyCache::new(Duration::from_secs(300))),
        event_proof_resolver,
    });

    let mut router = Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("metrics").get(metrics))
        .push(applet);

    if let Some(app_routes) = extra {
        router = router.push(app_routes);
    }

    let addr = format!(
        "{}:{}",
        ctx.config.bridge.bind_address, ctx.config.bridge.port
    );
    tracing::info!(%addr, "web service listening");

    let acceptor = TcpListener::new(addr).bind().await;
    Server::new(acceptor).serve(router).await;
    Err(BridgeError::Runtime(
        "web service exited unexpectedly".into(),
    ))
}

#[handler]
async fn health(res: &mut Response) {
    res.render(Json(serde_json::json!({ "status": "ok" })));
}

#[handler]
async fn metrics(res: &mut Response) {
    // Placeholder: can be wired to metrics-exporter-prometheus.
    res.render(Text::Plain("# cokret bridge metrics\n"));
}

#[derive(Clone)]
struct AppletWebState {
    handler: Arc<BridgeAppletHandler>,
    config: Arc<Config>,
    idempotency: Arc<TransactionIdempotencyCache>,
    event_proof_resolver: Arc<CompositeDidResolver>,
}

fn applet_router(state: AppletWebState) -> Router {
    Router::with_path("_cokret/edge/applet")
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

enum CachedTransaction {
    Pending {
        hash: String,
        expires_at: Instant,
    },
    Completed {
        hash: String,
        response: AppletTransactionOutcome,
        expires_at: Instant,
    },
}

impl CachedTransaction {
    fn expires_at(&self) -> Instant {
        match self {
            Self::Pending { expires_at, .. } | Self::Completed { expires_at, .. } => *expires_at,
        }
    }
}

struct TransactionIdempotencyCache {
    ttl: Duration,
    inner: Mutex<HashMap<String, CachedTransaction>>,
}

enum CachedTransactionLookup {
    Claimed,
    Pending,
    Duplicate(AppletTransactionOutcome),
    Conflict,
}

impl TransactionIdempotencyCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn claim(&self, source: &str, key: &str, hash: &str) -> CachedTransactionLookup {
        let cache_key = transaction_cache_key(source, key);
        let now = Instant::now();
        let mut inner = self.inner.lock();
        inner.retain(|_, cached| cached.expires_at() > now);
        match inner.get(&cache_key) {
            Some(CachedTransaction::Completed {
                hash: cached_hash,
                response,
                ..
            }) if cached_hash == hash => CachedTransactionLookup::Duplicate(response.clone()),
            Some(CachedTransaction::Pending {
                hash: cached_hash, ..
            }) if cached_hash == hash => CachedTransactionLookup::Pending,
            Some(_) => CachedTransactionLookup::Conflict,
            None => {
                inner.insert(
                    cache_key,
                    CachedTransaction::Pending {
                        hash: hash.to_owned(),
                        expires_at: now + self.ttl,
                    },
                );
                CachedTransactionLookup::Claimed
            }
        }
    }

    fn record(&self, source: &str, key: &str, hash: String, response: AppletTransactionOutcome) {
        self.inner.lock().insert(
            transaction_cache_key(source, key),
            CachedTransaction::Completed {
                hash,
                response,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    fn release(&self, source: &str, key: &str, hash: &str) {
        let cache_key = transaction_cache_key(source, key);
        let mut inner = self.inner.lock();
        let should_remove = matches!(
            inner.get(&cache_key),
            Some(CachedTransaction::Pending { hash: cached_hash, .. }) if cached_hash == hash
        );
        if should_remove {
            inner.remove(&cache_key);
        }
    }
}

fn transaction_cache_key(source: &str, key: &str) -> String {
    format!("{source}\u{1f}{key}")
}

#[handler]
async fn applet_ping(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = applet_state(depot, res) else {
        return;
    };
    if let Err(err) = verify_http_applet_get_request(req, &state.config) {
        unauthorized(res, err);
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
        unauthorized(res, err);
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
        return;
    };
    let Some(idempotency_key) = header_value(req, "idempotency-key")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        bad_request(res, "Idempotency-Key header is required");
        return;
    };

    let headers = collect_headers(req);
    let body_bytes = match req.payload().await {
        Ok(bytes) => bytes.to_vec(),
        Err(err) => {
            bad_request(res, format!("failed to read request body: {err}"));
            return;
        }
    };

    if let Err(err) = verify_http_transaction_request(req, &headers, &body_bytes, &state.config) {
        unauthorized(res, err);
        return;
    }

    let value: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            bad_request(res, format!("invalid JSON body: {err}"));
            return;
        }
    };
    let request_hash = match cokret::canonical::canonical_sha256(&value) {
        Ok(hash) => hash,
        Err(err) => {
            bad_request(res, format!("non-canonical transaction JSON: {err}"));
            return;
        }
    };
    let body: AppletTransactionRequestBody = match serde_json::from_value(value) {
        Ok(body) => body,
        Err(err) => {
            bad_request(res, format!("invalid transaction body: {err}"));
            return;
        }
    };

    let source = body.source_service_did.to_string();
    if source != state.config.cokret.trusted_server_did {
        unauthorized(res, "transaction source_service_did is not trusted");
        return;
    }

    match state
        .idempotency
        .claim(&source, &idempotency_key, &request_hash)
    {
        CachedTransactionLookup::Duplicate(response) => {
            res.render(Json(response));
            return;
        }
        CachedTransactionLookup::Pending => {
            res.render(Json(AppletTransactionOutcome {
                ok: false,
                rejected: Vec::new(),
                retry_after_ms: Some(1000),
            }));
            return;
        }
        CachedTransactionLookup::Conflict => {
            // Same (source_service_did, Idempotency-Key) with a different body:
            // applet-integration §7.3/§14 require the closed error code
            // `duplicate_conflict` (the registry has no `idempotency_conflict`).
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(json!({
                "ok": false,
                "rejected": [{ "reason": "duplicate_conflict" }]
            })));
            return;
        }
        CachedTransactionLookup::Claimed => {}
    }

    if let Err(err) = verify_transaction_events(state.event_proof_resolver.as_ref(), &body) {
        state
            .idempotency
            .release(&source, &idempotency_key, &request_hash);
        unauthorized(res, err);
        return;
    }

    match state
        .handler
        .handle_transaction(Some(&idempotency_key), body)
    {
        Ok(response) => {
            state
                .idempotency
                .record(&source, &idempotency_key, request_hash, response.clone());
            res.render(Json(response));
        }
        Err(err) => {
            state
                .idempotency
                .release(&source, &idempotency_key, &request_hash);
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
        unauthorized(res, err);
        return;
    }
    let actor_id = req.param::<String>("actor_id").unwrap_or_default();
    match state.handler.resolve_actor(&actor_id) {
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
        unauthorized(res, err);
        return;
    }
    let realm = req.param::<String>("realm_id_or_alias").unwrap_or_default();
    match state.handler.resolve_realm(&realm) {
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
        unauthorized(res, err);
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
        unauthorized(res, err);
        return;
    }
    unsupported_feature(
        res,
        "third_party user/location lookup is not implemented by this bridge",
    );
}

fn applet_state<'a>(depot: &'a Depot, res: &mut Response) -> Option<&'a AppletWebState> {
    match depot.obtain::<AppletWebState>() {
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
) -> std::result::Result<(), String> {
    verify_http_applet_request(req, headers, body, config, true)
}

fn verify_http_applet_get_request(
    req: &Request,
    config: &Config,
) -> std::result::Result<(), String> {
    let headers = collect_headers(req);
    verify_http_applet_request(req, &headers, &[], config, false)
}

fn verify_http_applet_request(
    req: &Request,
    headers: &[(String, String)],
    body: &[u8],
    config: &Config,
    require_content_digest: bool,
) -> std::result::Result<(), String> {
    let signature_input_header = header_value_from(headers, "signature-input")
        .ok_or_else(|| "Signature-Input header is required".to_owned())?;
    let signature_input =
        parse_signature_input(&signature_input_header).map_err(|err| err.to_string())?;
    let trusted_method = trusted_verification_method(config, &signature_input.key_id)?;
    let signer_did = verification_method_did(&signature_input.key_id)?;
    if signer_did != config.cokret.trusted_server_did {
        return Err("HTTP signature keyid is not owned by the trusted server DID".to_owned());
    }

    let origin = header_value_from(headers, "x-cokret-origin-service-did")
        .ok_or_else(|| "x-cokret-origin-service-did header is required".to_owned())?;
    if origin != config.cokret.trusted_server_did {
        return Err("HTTP signature origin service DID is not trusted".to_owned());
    }

    let destination = header_value_from(headers, "x-cokret-destination-service-did")
        .ok_or_else(|| "x-cokret-destination-service-did header is required".to_owned())?;
    if destination != config.cokret.service_did {
        return Err("HTTP signature destination service DID does not match this bridge".to_owned());
    }

    let public_key_bytes = trusted_method
        .public_key
        .ed25519_bytes()
        .map_err(|err| err.to_string())?;
    let public_key = public_key_from_bytes(&public_key_bytes).map_err(|err| err.to_string())?;
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
        Component::Header("x-cokret-origin-service-did".to_owned()),
        Component::Header("x-cokret-destination-service-did".to_owned()),
    ];
    if require_content_digest {
        required_components.push(Component::Header("content-digest".to_owned()));
    }
    let policy = SignatureVerificationPolicy::new(required_components)
        .require_content_digest(require_content_digest);
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
        chrono::Utc::now().timestamp(),
    )
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn verify_transaction_events(
    resolver: &CompositeDidResolver,
    body: &AppletTransactionRequestBody,
) -> std::result::Result<(), String> {
    let verifier = Ed25519DetachedJwsVerifier::new();
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
            verifier
                .verify_proof(proof, &canonical_bytes, &public_key)
                .map_err(|err| {
                    format!("event {} proof verification failed: {err}", event.event_id)
                })?;
        }
    }
    Ok(())
}

fn build_event_proof_resolver() -> Result<CompositeDidResolver> {
    let policy = ResolverPolicy {
        allowed_methods: vec![
            "did:key:".to_owned(),
            "did:web:".to_owned(),
            "did:webvh:".to_owned(),
        ],
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
) -> std::result::Result<&'a TrustedVerificationMethodConfig, String> {
    config
        .cokret
        .trusted_verification_methods
        .iter()
        .find(|method| method.verification_method == verification_method)
        .ok_or_else(|| format!("verification method {verification_method} is not trusted"))
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
) -> std::result::Result<String, String> {
    header_value_from(headers, "host")
        .or_else(|| {
            req.uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .ok_or_else(|| "request authority/Host is required".to_owned())
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn verification_method_lookup_accepts_full_fragment_and_single_key_documents() {
        let key = cokret::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]);

        let mut full = BTreeMap::new();
        full.insert("did:web:server.example#key-1".to_owned(), key.clone());
        assert_eq!(
            verification_method_value(&full, "did:web:server.example#key-1"),
            Some(key.as_str())
        );

        let mut fragment = BTreeMap::new();
        fragment.insert("#key-1".to_owned(), key.clone());
        assert_eq!(
            verification_method_value(&fragment, "did:web:server.example#key-1"),
            Some(key.as_str())
        );

        let mut single_did_key = BTreeMap::new();
        single_did_key.insert("unexpected-key-id".to_owned(), key.clone());
        let did_key_method = format!("did:key:{key}#{key}");
        assert_eq!(
            verification_method_value(&single_did_key, &did_key_method),
            Some(key.as_str())
        );

        let mut mismatched_web = BTreeMap::new();
        mismatched_web.insert("unexpected-key-id".to_owned(), key);
        assert_eq!(
            verification_method_value(&mismatched_web, "did:web:server.example#key-1"),
            None
        );
    }

    #[test]
    fn did_document_key_material_accepts_multibase_did_key_and_jwk_container() {
        let multibase = cokret::ed25519_pubkey_to_did_key_multibase(&[8u8; 32]);
        let public_key =
            public_key_material_from_did_document_value(&format!("did:key:{multibase}")).unwrap();
        assert_eq!(public_key.ed25519_bytes().unwrap(), [8u8; 32]);

        let jwk = serde_json::json!({
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": cokret::base64url_encode([9u8; 32]),
            }
        });
        let public_key = public_key_material_from_did_document_value(&jwk.to_string()).unwrap();
        assert_eq!(public_key.ed25519_bytes().unwrap(), [9u8; 32]);
    }

    #[test]
    fn idempotency_claim_blocks_duplicate_until_recorded() {
        let cache = TransactionIdempotencyCache::new(Duration::from_secs(300));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-1", "hash-a"),
            CachedTransactionLookup::Claimed
        ));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-1", "hash-a"),
            CachedTransactionLookup::Pending
        ));

        let response = AppletTransactionOutcome {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        };
        cache.record(
            "did:web:server.example",
            "idem-1",
            "hash-a".to_owned(),
            response.clone(),
        );

        match cache.claim("did:web:server.example", "idem-1", "hash-a") {
            CachedTransactionLookup::Duplicate(cached) => assert_eq!(cached.ok, response.ok),
            _ => panic!("expected duplicate response"),
        }
    }

    #[test]
    fn idempotency_release_allows_retry_after_failure() {
        let cache = TransactionIdempotencyCache::new(Duration::from_secs(300));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-2", "hash-a"),
            CachedTransactionLookup::Claimed
        ));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-2", "hash-b"),
            CachedTransactionLookup::Conflict
        ));

        cache.release("did:web:server.example", "idem-2", "hash-a");

        assert!(matches!(
            cache.claim("did:web:server.example", "idem-2", "hash-a"),
            CachedTransactionLookup::Claimed
        ));
    }
}

/// Render the spec standard error response shape
/// (`{"ok":false,"error":{"code":..,"message":..}}`, see
/// `service-http-binding.md` §9) with a registry error code. The protocol
/// surface (`/_cokret/edge/applet/*`) is part of the universal failure surface
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
