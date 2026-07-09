//! Configuration loading (YAML). The top-level structure is
//! `bridge` / `arkret` / `database` / `logging` plus a per-adapter `app`
//! section.

use std::fmt;
use std::path::{Path, PathBuf};

use arkret::signatures::PublicKeyMaterial;
use serde::Deserialize;

use crate::error::{BridgeError, Result};

/// Top-level configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub bridge: BridgeConfig,
    pub arkret: CokretConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Each app adapter's own configuration section (`auth`, tokens, etc.),
    /// kept as raw JSON and `deserialize`d into a strong type by the specific
    /// bridge.
    #[serde(default)]
    pub app: serde_json::Value,
    /// Static channel↔realm mappings applied (upserted) at startup. The messaging
    /// layer requires an explicit app-channel→Realm mapping for inbound delivery;
    /// this gives operators a supported, file-driven way to provision them
    /// instead of writing SQL by hand.
    #[serde(default)]
    pub mappings: Vec<ChannelRealmMappingConfig>,
}

/// A static channel↔realm mapping entry from configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct ChannelRealmMappingConfig {
    /// The app-side channel identifier (e.g. a Slack channel id or LINE group id).
    pub app_channel: String,
    /// The arkret realm id this channel maps to.
    pub realm_id: String,
    /// Optional portal alias.
    #[serde(default)]
    pub alias: Option<String>,
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
    /// When set, `ck.message.redact` events from arkret are not forwarded as
    /// app-side deletions (see `MessageAdapter::on_arkret_event`).
    #[serde(default)]
    pub disable_deletion_forwarding: bool,
    /// Per-source-IP rate limiting on the public webhook plane. Enabled by
    /// default with a deliberately generous quota; disable or widen it when a
    /// fronting reverse proxy already rate-limits, or when a platform's
    /// redelivery storms arrive from few source IPs.
    #[serde(default)]
    pub webhook_rate_limit: WebhookRateLimitConfig,
}

/// Per-source-IP rate limit settings for the public webhook plane.
#[derive(Clone, Debug, Deserialize)]
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
pub struct CokretConfig {
    /// The arkret edge/home server base URL (used for events_submit / blob /
    /// directory).
    pub server_url: String,
    /// The service DID of this bridge acting as an Applet.
    pub service_did: String,
    /// This bridge's applet id (`ck:applet:<uuidv7>`).
    pub applet_id: String,
    /// The Bearer access token used to submit events.
    pub access_token: String,
    /// The event signing private key seed (32 bytes, hexadecimal).
    pub signing_key_seed_hex: String,
    /// The signing verification method id (the kid on the DID).
    #[serde(default = "default_kid")]
    pub verification_method_id: String,
    /// The only arkret server DID accepted for server -> bridge transaction
    /// pushes.
    pub trusted_server_did: String,
    /// Static DID verification-method public keys accepted for HTTP message
    /// signatures and event envelope proofs on transaction pushes.
    #[serde(default)]
    pub trusted_verification_methods: Vec<TrustedVerificationMethodConfig>,
    /// Optional `ck.edge.applet.query.describe.namespaces` override. When omitted,
    /// the runtime publishes a narrow namespace derived from the bridge id and
    /// service DID.
    #[serde(default)]
    pub applet_namespaces: Option<serde_json::Value>,
    /// Optional `ck.edge.applet.query.describe.limits` override.
    #[serde(default)]
    pub applet_limits: Option<serde_json::Value>,
    /// Optional `ck.edge.applet.query.describe.auth` override.
    #[serde(default)]
    pub applet_auth: Option<serde_json::Value>,
}

/// A configured verification method and its Ed25519 public key material.
#[derive(Clone, Debug, Deserialize)]
pub struct TrustedVerificationMethodConfig {
    pub verification_method: String,
    pub public_key: PublicKeyMaterial,
}

impl fmt::Debug for CokretConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretConfig")
            .field("server_url", &self.server_url)
            .field("service_did", &self.service_did)
            .field("applet_id", &self.applet_id)
            .field("access_token", &"<redacted>")
            .field("signing_key_seed_hex", &"<redacted>")
            .field("verification_method_id", &self.verification_method_id)
            .field("trusted_server_did", &self.trusted_server_did)
            .field(
                "trusted_verification_methods",
                &self.trusted_verification_methods,
            )
            .field("applet_namespaces", &self.applet_namespaces)
            .field("applet_limits", &self.applet_limits)
            .field("applet_auth", &self.applet_auth)
            .finish()
    }
}

/// Database configuration. `url` looks like `sqlite://bridge.db` /
/// `postgres://...` / `mysql://...`.
#[derive(Clone, Debug, Deserialize)]
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

    pub fn from_yaml(text: &str) -> Result<Self> {
        Self::from_yaml_with_base_dir(text, None)
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
  applet_id: "ak:applet:01904100-0000-7000-8000-000000000001"
  access_token: "token"
  signing_key_seed_hex: "1111111111111111111111111111111111111111111111111111111111111111"
  verification_method_id: "#key-1"
  trusted_server_did: "did:webvh:server.example"
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
        let config = Config::from_yaml(&text).unwrap();

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
        let config = Config::from_yaml(&text).unwrap();

        assert_eq!(config.app["path_copy"], expected.as_ref());
    }

    #[test]
    fn config_rejects_missing_env_references() {
        let text = minimal_config("app:\n  secret: \"env:ARKRET_BRIDGE_TEST_MISSING_ENV\"\n");
        let err = Config::from_yaml(&text).unwrap_err();

        assert!(format!("{err}").contains("ARKRET_BRIDGE_TEST_MISSING_ENV"));
    }
}
