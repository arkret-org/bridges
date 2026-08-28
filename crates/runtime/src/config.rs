//! Configuration loading (YAML). The top-level structure is
//! `bridge` / `arkret` / `database` / `logging` plus a per-adapter `app`
//! section.

use std::fmt;
use std::path::{Path, PathBuf};

use arkret::Did;
use arkret::signatures::PublicKeyMaterial;
use arkret_models_integration::AppletWireNamespaces;
use arkret_wire::DidUrl;
use serde::Deserialize;

use crate::error::{BridgeError, Result};

/// Top-level configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub bridge: BridgeConfig,
    pub arkret: ArkretConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Each app adapter's own configuration section (`auth`, tokens, etc.),
    /// kept as raw JSON and `deserialize`d into a strong type by the specific
    /// bridge.
    #[serde(default)]
    pub app: serde_json::Value,
    /// Product-layer extensions retained without giving the generic runtime
    /// ownership of their semantics.
    #[serde(default, flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// The bridge's own general configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct BridgeConfig {
    /// The bridge identifier (e.g. `discord`), used for applet_id / namespace
    /// prefixes.
    pub bridge_id: String,
    /// Optional upstream tenant/workspace/team identifier. When omitted, the
    /// bridge's Arkret service DID is used as the tenant boundary for external
    /// event deduplication.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Public webhook listen port. The webhook plane (`/webhooks/*`, plus the
    /// Teams Bot Framework `/api/messages`) binds here; it must be reachable by
    /// the external platforms that call back into the bridge.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Public webhook bind address. Defaults to `0.0.0.0` because this plane is
    /// expected to face the platform callbacks (behind a reverse proxy).
    #[serde(default = "default_webhook_bind")]
    pub webhook_bind: String,
    /// Internal admin/edge listen port. The trusted applet protocol plane
    /// (`/_arkret/edge/applet/*`) and the ops plane (`/health` + `/metrics`)
    /// bind here, separated from the public webhook plane so that "no reverse
    /// proxy configured" still yields plane isolation by default. When omitted,
    /// it falls back to `port + 1000`.
    #[serde(default)]
    pub admin_port: Option<u16>,
    /// Internal bind address for the applet protocol plane and the ops plane.
    /// Defaults to `127.0.0.1` (loopback) so these planes are not reachable from
    /// the public network unless an operator explicitly opens them.
    #[serde(default = "default_admin_bind")]
    pub admin_bind: String,
    /// Per-source-IP rate limiting on the public webhook plane. Enabled by
    /// default with a deliberately generous quota; disable or widen it when a
    /// fronting reverse proxy already rate-limits, or when a platform's
    /// redelivery storms arrive from few source IPs.
    #[serde(default)]
    pub webhook_rate_limit: WebhookRateLimitConfig,
    /// Product-layer bridge extensions retained for the owning adapter layer.
    #[serde(default, flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// Per-source-IP rate limit settings for the public webhook plane.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookRateLimitConfig {
    /// Master switch; `true` by default ("isolated by default" extends to
    /// "rate-limited by default").
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    /// Requests allowed per source IP per window. The default (600/min, i.e. a
    /// sustained 10 rps per IP) is far above any legitimate per-tenant webhook
    /// rate while still bounding a single-source flood.
    #[serde(default = "default_rate_limit_requests")]
    pub max_requests: usize,
    /// Window length in seconds.
    #[serde(default = "default_rate_limit_window_secs")]
    pub window_secs: u16,
}

impl Default for WebhookRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            max_requests: default_rate_limit_requests(),
            window_secs: default_rate_limit_window_secs(),
        }
    }
}

fn default_rate_limit_enabled() -> bool {
    true
}
fn default_rate_limit_requests() -> usize {
    600
}
fn default_rate_limit_window_secs() -> u16 {
    60
}

impl BridgeConfig {
    /// The public webhook plane listen address (`webhook_bind:port`).
    pub fn webhook_addr(&self) -> String {
        format!("{}:{}", self.webhook_bind, self.port)
    }

    /// The effective internal admin/edge port. When `admin_port` is unset it
    /// falls back to `port + 1000` (saturating), keeping the applet protocol
    /// plane and the ops plane on a distinct, predictable internal port so the
    /// default loopback bind does not collide with the public webhook plane.
    pub fn effective_admin_port(&self) -> u16 {
        self.admin_port
            .unwrap_or_else(|| self.port.saturating_add(1000))
    }

    /// The internal admin/edge plane listen address (`admin_bind:admin_port`).
    pub fn admin_addr(&self) -> String {
        format!("{}:{}", self.admin_bind, self.effective_admin_port())
    }
}

/// arkret protocol-side integration parameters (server URL, service DID,
/// applet id, signing material).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkretConfig {
    /// The arkret edge/home server base URL (used for events_submit / blob /
    /// directory).
    pub server_url: String,
    /// The service DID of this bridge acting as an Applet.
    pub service_did: Did,
    /// Trust domain advertised by the applet service description.
    pub trust_domain: arkret::TrustDomainId,
    /// This bridge's applet id (`ak:applet:<uuidv7>`).
    pub applet_id: String,
    /// The Bearer access token used to submit events.
    pub access_token: String,
    /// The event signing private key seed (32 bytes, hexadecimal).
    pub signing_key_seed_hex: String,
    /// The signing verification method id (the kid on the DID).
    #[serde(default = "default_kid")]
    pub verification_method_fragment: String,
    /// The only arkret server DID accepted for server -> bridge transaction
    /// pushes.
    pub trusted_server_did: Did,
    /// Static DID verification-method public keys accepted for HTTP message
    /// signatures and event envelope proofs on transaction pushes.
    #[serde(default)]
    pub trusted_verification_methods: Vec<TrustedVerificationMethodConfig>,
    /// Exact namespace claims from the installed canonical Applet package.
    /// There is no service-DID-derived fallback: omitting this field is a
    /// startup configuration error.
    pub applet_namespaces: AppletWireNamespaces,
    /// Applet-owned managed-actor identity authoring and key-custody settings.
    /// Messaging bridges require this because a first-seen external user must
    /// be materialized as a real Ghost actor before its Event can be submitted.
    pub managed_actor_authoring: ManagedActorAuthoringConfig,
}

/// Durable Applet-managed actor identity configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedActorAuthoringConfig {
    /// Public HTTPS base used in managed `did:webvh` identities. The generated
    /// DID is checked against the installed Applet actor namespace before any
    /// key or authoring result becomes visible.
    pub principal_endpoint: String,
    /// 32-byte hexadecimal key encrypting managed-actor root/next seeds at
    /// rest. It is deliberately separate from the Applet service signing key.
    pub key_encryption_key_hex: String,
}

impl ManagedActorAuthoringConfig {
    pub fn principal_endpoint(&self) -> Result<url::Url> {
        let endpoint = url::Url::parse(&self.principal_endpoint).map_err(|error| {
            BridgeError::Config(format!(
                "managed_actor_authoring.principal_endpoint: {error}"
            ))
        })?;
        if endpoint.scheme() != "https"
            && !matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        {
            return Err(BridgeError::Config(
                "managed_actor_authoring.principal_endpoint must use https; only loopback may use http"
                    .to_owned(),
            ));
        }
        Ok(endpoint)
    }

    pub fn key_encryption_key(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.key_encryption_key_hex).map_err(|error| {
            BridgeError::Config(format!(
                "managed_actor_authoring.key_encryption_key_hex must be hexadecimal: {error}"
            ))
        })?;
        bytes.try_into().map_err(|_| {
            BridgeError::Config(
                "managed_actor_authoring.key_encryption_key_hex must encode exactly 32 bytes"
                    .to_owned(),
            )
        })
    }
}

impl fmt::Debug for ManagedActorAuthoringConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedActorAuthoringConfig")
            .field("principal_endpoint", &self.principal_endpoint)
            .field("key_encryption_key_hex", &"<redacted>")
            .finish()
    }
}

impl ArkretConfig {
    /// The `#fragment` of the configured signing verification method.
    ///
    /// `verification_method_fragment` is configured as a bare fragment (`#key-1`) of
    /// this Applet service DID. Ghost key custody belongs to the separately
    /// installed Applet-managed authoring provider.
    pub fn verification_method_fragment(&self) -> Result<&str> {
        let (_, fragment) = self
            .verification_method_fragment
            .rsplit_once('#')
            .ok_or_else(|| {
                BridgeError::Config(
                    "verification_method_fragment must contain a #key fragment".to_owned(),
                )
            })?;
        if fragment.trim().is_empty() {
            return Err(BridgeError::Config(
                "verification_method_fragment key fragment must not be empty".to_owned(),
            ));
        }
        Ok(fragment)
    }

    /// The absolute signing DID URL for `actor`.
    ///
    /// `DidUrl` is the wire type for `verification_method`
    /// (`did-usage-and-verification.md` §2.2); a bare DID or a bare `#fragment`
    /// is rejected at construction rather than travelling as a `String`.
    pub fn verification_method_for(&self, actor: &Did) -> Result<DidUrl> {
        let fragment = self.verification_method_fragment()?;
        DidUrl::new(format!("{}#{fragment}", actor.as_str())).map_err(|err| {
            BridgeError::Config(format!(
                "verification_method_fragment does not form a valid DID URL for `{actor}`: {err}"
            ))
        })
    }
}

/// A configured verification method and its Ed25519 public key material.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedVerificationMethodConfig {
    pub verification_method: DidUrl,
    pub public_key: PublicKeyMaterial,
}

impl fmt::Debug for ArkretConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArkretConfig")
            .field("server_url", &self.server_url)
            .field("service_did", &self.service_did)
            .field("trust_domain", &self.trust_domain)
            .field("applet_id", &self.applet_id)
            .field("access_token", &"<redacted>")
            .field("signing_key_seed_hex", &"<redacted>")
            .field(
                "verification_method_fragment",
                &self.verification_method_fragment,
            )
            .field("trusted_server_did", &self.trusted_server_did)
            .field(
                "trusted_verification_methods",
                &self.trusted_verification_methods,
            )
            .field("applet_namespaces", &self.applet_namespaces)
            .field("managed_actor_authoring", &self.managed_actor_authoring)
            .finish()
    }
}

/// Database configuration. `url` looks like `sqlite://bridge.db` /
/// `postgres://...`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_url")]
    pub url: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_db_url(),
            pool_size: default_pool_size(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_port() -> u16 {
    9100
}
fn default_webhook_bind() -> String {
    "0.0.0.0".to_owned()
}
fn default_admin_bind() -> String {
    "127.0.0.1".to_owned()
}
fn default_kid() -> String {
    "#key-1".to_owned()
}
fn default_db_url() -> String {
    "sqlite://bridge.db".to_owned()
}
fn default_pool_size() -> u32 {
    8
}
fn default_log_level() -> String {
    "info".to_owned()
}
fn default_log_format() -> String {
    "pretty".to_owned()
}

impl Config {
    /// Load a YAML configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| BridgeError::Config(format!("reading {}: {e}", path.display())))?;
        Self::from_yaml_with_base_dir(&text, path.parent())
    }

    fn from_yaml_with_base_dir(text: &str, base_dir: Option<&Path>) -> Result<Self> {
        let mut value: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(text).map_err(|e| BridgeError::Config(e.to_string()))?;
        resolve_config_references(&mut value, base_dir)?;
        serde_yaml_ng::from_value(value).map_err(|e| BridgeError::Config(e.to_string()))
    }

    /// Decode the signing seed into 32 bytes.
    ///
    /// Rejects the all-zero seed: it appears verbatim in the sample configs, so
    /// an operator who copies a sample without changing it would otherwise run
    /// with a publicly predictable signing key.
    pub fn signing_seed(&self) -> Result<[u8; 32]> {
        let bytes = hex_decode(&self.arkret.signing_key_seed_hex).ok_or_else(|| {
            BridgeError::Config("signing_key_seed_hex is not valid hexadecimal".into())
        })?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BridgeError::Config("signing_key_seed_hex must be 32 bytes".into()))?;
        if seed == [0u8; 32] {
            return Err(BridgeError::Config(
                "signing_key_seed_hex must not be all-zero (replace the sample placeholder)".into(),
            ));
        }
        Ok(seed)
    }
}

fn resolve_config_references(
    value: &mut serde_yaml_ng::Value,
    base_dir: Option<&Path>,
) -> Result<()> {
    match value {
        serde_yaml_ng::Value::String(s) => {
            *s = resolve_config_string(s, base_dir)?;
        }
        serde_yaml_ng::Value::Sequence(items) => {
            for item in items {
                resolve_config_references(item, base_dir)?;
            }
        }
        serde_yaml_ng::Value::Mapping(map) => {
            for value in map.values_mut() {
                resolve_config_references(value, base_dir)?;
            }
        }
        serde_yaml_ng::Value::Null
        | serde_yaml_ng::Value::Bool(_)
        | serde_yaml_ng::Value::Number(_) => {}
        serde_yaml_ng::Value::Tagged(tagged) => {
            resolve_config_references(&mut tagged.value, base_dir)?;
        }
    }
    Ok(())
}

fn resolve_config_string(value: &str, base_dir: Option<&Path>) -> Result<String> {
    let value = interpolate_env_vars(value)?;
    if let Some(name) = value.strip_prefix("env:") {
        let name = name.trim();
        if name.is_empty() {
            return Err(BridgeError::Config("empty env: reference".to_owned()));
        }
        return std::env::var(name).map_err(|err| {
            BridgeError::Config(format!("environment variable {name} is not set: {err}"))
        });
    }
    if let Some(path) = value.strip_prefix("file:") {
        let path = path.trim();
        if path.is_empty() {
            return Err(BridgeError::Config("empty file: reference".to_owned()));
        }
        let path = resolve_config_file_path(path, base_dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|err| BridgeError::Config(format!("reading {}: {err}", path.display())))?;
        return Ok(text.trim_end_matches(['\r', '\n']).to_owned());
    }
    Ok(value)
}

fn resolve_config_file_path(path: &str, base_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else if let Some(base_dir) = base_dir {
        base_dir.join(path)
    } else {
        path
    }
}

fn interpolate_env_vars(value: &str) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(BridgeError::Config(
                "unterminated ${...} reference".to_owned(),
            ));
        };
        let name = after_start[..end].trim();
        if name.is_empty() {
            return Err(BridgeError::Config("empty ${...} reference".to_owned()));
        }
        let replacement = std::env::var(name).map_err(|err| {
            BridgeError::Config(format!("environment variable {name} is not set: {err}"))
        })?;
        out.push_str(&replacement);
        rest = &after_start[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    // Operate on bytes (not the str) so multi-byte UTF-8 input cannot panic on a
    // non-char-boundary slice; non-ASCII hex digits simply fail `from_str_radix`.
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(extra: &str) -> String {
        format!(
            r##"
bridge:
  bridge_id: test
arkret:
  server_url: "https://example.test"
  service_did: "did:webvh:bridge.example"
  trust_domain: "ak:trust_domain:example.net"
  applet_id: "ak:applet:01904100-0000-7000-8000-000000000001"
  access_token: "token"
  signing_key_seed_hex: "1111111111111111111111111111111111111111111111111111111111111111"
  verification_method_fragment: "#key-1"
  trusted_server_did: "did:webvh:server.example"
  applet_namespaces:
    actors: []
    realms: []
    handles: []
  managed_actor_authoring:
    principal_endpoint: "https://managed-actors.example/identities/"
    key_encryption_key_hex: "2222222222222222222222222222222222222222222222222222222222222222"
{extra}
"##
        )
    }

    #[test]
    fn config_resolves_file_references() {
        let path = std::env::temp_dir().join(format!(
            "arkret-bridge-config-secret-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "from-file\n").unwrap();
        let yaml_path = path.to_string_lossy().replace('\\', "/");

        let text = minimal_config(&format!("app:\n  webhook_secret: \"file:{yaml_path}\"\n",));
        let config = Config::from_yaml_with_base_dir(&text, None).unwrap();

        assert_eq!(config.app["webhook_secret"], "from-file");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn config_resolves_env_references_inside_strings() {
        let Some(path) = std::env::var_os("PATH") else {
            return;
        };
        let expected = path.to_string_lossy();
        let text = minimal_config("app:\n  path_copy: \"${PATH}\"\n");
        let config = Config::from_yaml_with_base_dir(&text, None).unwrap();

        assert_eq!(config.app["path_copy"], expected.as_ref());
    }

    #[test]
    fn config_rejects_missing_env_references() {
        let text = minimal_config("app:\n  secret: \"env:ARKRET_BRIDGE_TEST_MISSING_ENV\"\n");
        let err = Config::from_yaml_with_base_dir(&text, None).unwrap_err();

        assert!(format!("{err}").contains("ARKRET_BRIDGE_TEST_MISSING_ENV"));
    }

    #[test]
    fn webhook_rate_limit_config_rejects_misspelled_security_keys() {
        let error = serde_yaml_ng::from_str::<WebhookRateLimitConfig>(
            "enabled: true\nmax_request: 10\nwindow_secs: 60\n",
        )
        .expect_err("a misspelled rate-limit key must not silently use the default");

        assert!(error.to_string().contains("unknown field `max_request`"));
    }

    #[test]
    fn config_requires_explicit_applet_namespaces() {
        let text = minimal_config("").replace(
            "  applet_namespaces:\n    actors: []\n    realms: []\n    handles: []\n",
            "",
        );
        let error = Config::from_yaml_with_base_dir(&text, None)
            .expect_err("missing canonical Applet namespaces must fail closed");

        assert!(error.to_string().contains("applet_namespaces"));
    }
}
