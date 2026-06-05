//! Configuration loading. Supports YAML (`config.yaml`) and KDL
//! (`config.kdl`), with the parser chosen by file extension. The top-level
//! structure is `bridge` / `cokret` / `database` / `logging` plus a per-adapter
//! `app` section.

use std::{fmt, path::Path};

use serde::Deserialize;

use crate::error::{BridgeError, Result};

/// Top-level configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub bridge: BridgeConfig,
    pub cokret: CokretConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Each app adapter's own configuration section (`auth`, tokens, etc.),
    /// kept as raw JSON and `deserialize`d into a strong type by the specific
    /// bridge.
    #[serde(default)]
    pub app: serde_json::Value,
}

/// The bridge's own general configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct BridgeConfig {
    /// The bridge identifier (e.g. `discord`), used for applet_id / namespace
    /// prefixes.
    pub bridge_id: String,
    /// Optional upstream tenant/workspace/team identifier. When omitted, the
    /// bridge's Cokret service DID is used as the tenant boundary for external
    /// event deduplication.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// HTTP listen port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// HTTP bind address.
    #[serde(default = "default_bind")]
    pub bind_address: String,
    /// The administrator's cokret DID.
    #[serde(default)]
    pub admin_did: Option<String>,
    #[serde(default)]
    pub disable_presence: bool,
    #[serde(default)]
    pub disable_typing_notifications: bool,
    #[serde(default)]
    pub disable_read_receipts: bool,
    #[serde(default)]
    pub disable_deletion_forwarding: bool,
}

/// cokret protocol-side integration parameters (server URL, service DID,
/// applet id, signing material).
#[derive(Clone, Deserialize)]
pub struct CokretConfig {
    /// The cokret edge/home server base URL (used for events_submit / blob /
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
    /// The realm this bridge belongs to by default (fallback when there is no
    /// mapping).
    #[serde(default)]
    pub default_realm_id: Option<String>,
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
            .field("default_realm_id", &self.default_realm_id)
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
fn default_bind() -> String {
    "0.0.0.0".to_owned()
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
    /// Load from a file, choosing the parser by extension (`.kdl` / otherwise
    /// YAML).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| BridgeError::Config(format!("reading {}: {e}", path.display())))?;
        if path.extension().and_then(|s| s.to_str()) == Some("kdl") {
            Self::from_kdl(&text)
        } else {
            Self::from_yaml(&text)
        }
    }

    pub fn from_yaml(text: &str) -> Result<Self> {
        serde_yaml::from_str(text).map_err(|e| BridgeError::Config(e.to_string()))
    }

    /// KDL → JSON → Config. Only supports the simple scalar/nested-node shapes
    /// used by this configuration.
    pub fn from_kdl(text: &str) -> Result<Self> {
        let doc: kdl::KdlDocument = text
            .parse()
            .map_err(|e: kdl::KdlError| BridgeError::Config(e.to_string()))?;
        let value = kdl_doc_to_json(&doc);
        serde_json::from_value(value).map_err(|e| BridgeError::Config(e.to_string()))
    }

    /// Decode the signing seed into 32 bytes.
    ///
    /// Rejects the all-zero seed: it appears verbatim in the sample configs, so
    /// an operator who copies a sample without changing it would otherwise run
    /// with a publicly predictable signing key.
    pub fn signing_seed(&self) -> Result<[u8; 32]> {
        let bytes = hex_decode(&self.cokret.signing_key_seed_hex).ok_or_else(|| {
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

/// Convert a KDL document into a JSON object: each node name becomes a key; a
/// leaf node takes its first argument as a scalar; a node with children is
/// recursed into an object. This is sufficient to cover the hierarchy of this
/// configuration.
fn kdl_doc_to_json(doc: &kdl::KdlDocument) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for node in doc.nodes() {
        let name = node.name().value().to_owned();
        let value = if let Some(children) = node.children() {
            kdl_doc_to_json(children)
        } else if let Some(entry) = node.entries().first() {
            kdl_value_to_json(entry.value())
        } else {
            serde_json::Value::Null
        };
        map.insert(name, value);
    }
    serde_json::Value::Object(map)
}

fn kdl_value_to_json(v: &kdl::KdlValue) -> serde_json::Value {
    if let Some(s) = v.as_string() {
        serde_json::Value::String(s.to_owned())
    } else if let Some(i) = v.as_i64() {
        serde_json::Value::from(i)
    } else if let Some(f) = v.as_f64() {
        serde_json::Value::from(f)
    } else if let Some(b) = v.as_bool() {
        serde_json::Value::Bool(b)
    } else {
        serde_json::Value::Null
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
