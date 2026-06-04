//! The cokret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> cokret)**: [`CokretEdge::mint_event`] /
//!   [`CokretEdge::submit`] build and sign an `Event` and submit it via
//!   [`cokret::http_client::Client::events_submit`].
//! - **Inbound (cokret → app)**: transactions pushed by the cokret server via
//!   the applet HTTP endpoints are placed into the `inbound_tx` queue by
//!   [`BridgeAppletHandler`]; after the core consumes them they are forwarded
//!   to the app adapter.
//! - **Media**: [`CokretEdge::upload_blob`] / [`CokretEdge::download_blob`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cokret::Ed25519MoveSigner;
use cokret::http_client::{Auth, Client};
use cokret::model::{
    AppletActorResBody, AppletDescription, AppletPingResBody, AppletProtocolResBody,
    AppletRealmResBody, AppletTransactionReqBody, AppletTransactionResBody,
};
use cokret::signatures::{SignEventOptions, sign_event};
use cokret::{Did, Event, Hlc, RealmId};
use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::Config;
use crate::error::{BridgeError, Result};

/// The cokret edge client.
pub struct CokretEdge {
    config: Arc<Config>,
    client: Client,
    signer: Ed25519MoveSigner,
    service_did: Did,
    node_id: String,
    /// The incrementing sequence number of this bridge's service actor (+1 per
    /// event).
    actor_seq: AtomicU64,
    /// The HLC logical counter.
    logical: AtomicU64,
    /// Inbound event queue: cokret server push → core consumer loop.
    inbound_tx: UnboundedSender<Event>,
}

impl CokretEdge {
    pub fn new(config: Arc<Config>, inbound_tx: UnboundedSender<Event>) -> Result<Self> {
        let base = url::Url::parse(&config.cokret.server_url)
            .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
        let client = Client::builder(base)
            .auth(Auth::Bearer(config.cokret.access_token.clone()))
            .build()?;

        let service_did = Did::new(config.cokret.service_did.clone())?;
        let seed = config.signing_seed()?;
        let signer = Ed25519MoveSigner::from_did_key_seed(
            seed,
            service_did.clone(),
            config.cokret.verification_method_id.clone(),
        );

        // Derive a stable 8-digit hexadecimal HLC node id from bridge_id.
        let node_id = stable_node_id(&config.bridge.bridge_id);

        Ok(Self {
            config,
            client,
            signer,
            service_did,
            node_id,
            actor_seq: AtomicU64::new(1),
            logical: AtomicU64::new(0),
            inbound_tx,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn service_did(&self) -> &Did {
        &self.service_did
    }

    pub fn inbound_sender(&self) -> UnboundedSender<Event> {
        self.inbound_tx.clone()
    }

    /// Generate the next HLC (`{ms:012x}-{logical:04x}-{node:08x}`).
    fn next_hlc(&self) -> Result<Hlc> {
        let ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let logical = self.logical.fetch_add(1, Ordering::Relaxed) % 0x1_0000;
        let raw = format!(
            "{:012x}-{:04x}-{}",
            ms & 0xFFFF_FFFF_FFFF,
            logical,
            self.node_id
        );
        Hlc::new(raw).map_err(Into::into)
    }

    /// Build and sign an event emitted by this bridge's service actor.
    pub fn mint_event(&self, kind: &str, realm_id: &RealmId, content: Value) -> Result<Event> {
        let seq = self.actor_seq.fetch_add(1, Ordering::Relaxed);
        let hlc = self.next_hlc()?;
        let mut event = Event::new(
            kind,
            realm_id.clone(),
            self.service_did.clone(),
            seq,
            hlc,
            content,
        )?;
        event.applet_id = Some(self.config.cokret.applet_id.clone());
        sign_event(
            &mut event,
            &self.signer,
            &self.config.cokret.verification_method_id,
            SignEventOptions::new(),
        )?;
        Ok(event)
    }

    /// Outbound: submit an already-minted event and return its event_id.
    /// Generic over event kind — carries no messaging assumptions.
    pub async fn submit_event(&self, event: &Event) -> Result<String> {
        let event_id = event.event_id.to_string();
        self.client.events_submit(event).await?;
        Ok(event_id)
    }

    /// Outbound convenience: mint + sign + submit an event of `kind` into
    /// `realm_id` with `content`. Returns the event_id.
    pub async fn submit(&self, realm_id: &str, kind: &str, content: Value) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let event = self.mint_event(kind, &realm, content)?;
        self.submit_event(&event).await
    }

    /// Outbound convenience with signed bridge provenance. `external_ref` is
    /// written before signing, so upstream ids and actor/channel evidence are
    /// part of the event transcript.
    pub async fn submit_with_external_ref(
        &self,
        realm_id: &str,
        kind: &str,
        content: Value,
        external_ref: Value,
    ) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let mut event = self.mint_event(kind, &realm, content)?;
        event.external_ref = Some(external_ref);
        event.proofs.clear();
        sign_event(
            &mut event,
            &self.signer,
            &self.config.cokret.verification_method_id,
            SignEventOptions::new(),
        )?;
        self.submit_event(&event).await
    }

    /// Outbound: redact a previously submitted event by id.
    pub async fn submit_redaction(&self, realm_id: &str, target_event_id: &str) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let content = serde_json::json!({ "target_event_id": target_event_id });
        let mut event = self.mint_event("ck.message.redact", &realm, content)?;
        event.redacts = Some(cokret::EventId::new(target_event_id.to_owned())?);
        // redacts is set after minting, so re-sign to override.
        event.proofs.clear();
        sign_event(
            &mut event,
            &self.signer,
            &self.config.cokret.verification_method_id,
            SignEventOptions::new(),
        )?;
        self.submit_event(&event).await
    }

    /// Media upload: returns the blob reference string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        let meta = cokret::model::BlobUploadMetadata {
            realm_id: None,
            content_digest: None,
            size_bytes: bytes.len() as u64,
            media_type: Some(mime.to_owned()),
            filename: None,
            purpose: None,
        };
        let res = self.client.blob_upload_bytes(&meta, bytes.to_vec()).await?;
        Ok(res.blob_ref.to_string())
    }

    /// Media download.
    pub async fn download_blob(&self, blob_ref: &str) -> Result<Vec<u8>> {
        let r = cokret::BlobRef::new(blob_ref.to_owned())?;
        Ok(self.client.blob_download(&r, None).await?)
    }
}

/// [`stable_node_id`] maps any bridge_id to an 8-digit lower-hex value.
fn stable_node_id(bridge_id: &str) -> String {
    // A simple FNV-1a 32-bit hash, to avoid pulling in extra dependencies.
    let mut hash: u32 = 0x811c_9dc5;
    for b in bridge_id.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

/// The receiver for transactions pushed by the cokret server (implements
/// [`cokret::AppletHandler`]). It delivers the events in a transaction to the
/// inbound queue; the business forwarding is done in the core consumer loop.
pub struct BridgeAppletHandler {
    applet_id: String,
    service_did: Did,
    protocols: Vec<String>,
    inbound_tx: UnboundedSender<Event>,
}

impl BridgeAppletHandler {
    pub fn new(edge: &CokretEdge) -> Self {
        Self {
            applet_id: edge.config.cokret.applet_id.clone(),
            service_did: edge.service_did.clone(),
            protocols: vec![edge.config.bridge.bridge_id.clone()],
            inbound_tx: edge.inbound_sender(),
        }
    }
}

impl cokret::AppletHandler for BridgeAppletHandler {
    fn ping(&self) -> cokret::Result<AppletPingResBody> {
        Ok(AppletPingResBody {
            ok: true,
            applet_id: self.applet_id.clone(),
            service_did: self.service_did.clone(),
            protocol_version: "1.0".to_owned(),
        })
    }

    fn describe(&self) -> cokret::Result<AppletDescription> {
        Ok(AppletDescription {
            applet_id: self.applet_id.clone(),
            service_did: self.service_did.clone(),
            protocols: self.protocols.clone(),
            namespaces: Value::Null,
            limits: Value::Null,
            auth: Value::Null,
        })
    }

    fn handle_transaction(
        &self,
        _idempotency_key: Option<&str>,
        req: AppletTransactionReqBody,
    ) -> cokret::Result<AppletTransactionResBody> {
        for event in req.events {
            // A full queue / closed receiver is only logged and does not block
            // transaction acknowledgement.
            let _ = self.inbound_tx.send(event);
        }
        Ok(AppletTransactionResBody {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        })
    }

    fn resolve_actor(&self, _actor_id: &str) -> cokret::Result<AppletActorResBody> {
        Ok(AppletActorResBody {
            exists: false,
            actor_id: None,
            display_name: None,
            external_ref: Value::Null,
        })
    }

    fn resolve_realm(&self, _realm_id_or_alias: &str) -> cokret::Result<AppletRealmResBody> {
        Ok(AppletRealmResBody {
            exists: false,
            realm_id: None,
            title: None,
            external_ref: Value::Null,
        })
    }

    fn resolve_protocol(&self, protocol: &str) -> cokret::Result<AppletProtocolResBody> {
        Ok(AppletProtocolResBody {
            protocol: protocol.to_owned(),
            display_name: protocol.to_owned(),
            icon_blob_ref: None,
            field_types: Value::Null,
            instances: Vec::new(),
        })
    }
}
