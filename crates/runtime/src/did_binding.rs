//! Operator-pinned Service bindings for startup and management discovery.
//!
//! Realm creation completions use the async verified governance adapter in
//! `realm_governance`: a locally frozen creation selects the Realm, then its
//! authenticated handoff chain selects the current Station. The bindings in
//! this module alone never authorize a Realm creation completion or a Device.
//! Ordinary signature lookup remains resolver-free. No Event signer obtains
//! authority merely because its key appears in a DID document.

use std::sync::Arc;

use arkret::identity::{
    AcceptedDidBinding, BindingInvalidation, DidBindingEvidenceReceipt, DidBindingPurpose,
    DidBindingStatus, DidDocument, InMemoryVerifiedDidBindingStore, LimitedTrust, MethodEvidence,
    ResolverFailMode, ResolverPolicy, VerifiedDidBinding, VerifiedDidBindingDocumentInput,
    VerifiedDidBindingKey, VerifiedDidBindingStore, document_canonical_digest, policy_digest,
};
use arkret::{Did, Hash, TrustDomainId};
use arkret_wire::DidUrl;
use chrono::{DateTime, Utc};

use crate::error::{BridgeError, Result};

/// Upper bound on distinct accepted bindings held in memory. Inbound pushes
/// come from one trusted node but may carry Events from many actors, so the
/// store is bounded (deterministic oldest-`verified_at` eviction) rather than
/// unbounded.
const BINDING_STORE_CAPACITY: usize = 4096;

/// The acceptance policy every inbound DID binding is made under.
///
/// There is no resolver on this path, but the policy is still the
/// `policy_digest` dimension of a [`VerifiedDidBindingKey`]: it records which
/// DID methods a binding was accepted for and that the path is fail-closed.
/// Workspace-wide rule: actor / service identities are `did:webvh` only
/// (`did:web` is not an accepted alias); `did:key` stays for bare
/// verification-method keys.
fn inbound_binding_policy() -> ResolverPolicy {
    ResolverPolicy {
        allowed_methods: vec!["did:key:".to_owned(), "did:webvh:".to_owned()],
        fail_mode: ResolverFailMode::FailClosed,
        ..ResolverPolicy::default()
    }
}

/// Canonical digest of the effective acceptance policy.
///
/// This is the `policy_digest` dimension of [`VerifiedDidBindingKey`]: a policy
/// revision changes the digest, which changes the key, so a binding accepted
/// under an older policy is never silently reused (§5: a Realm resolver-policy
/// change must invalidate affected bindings).
///
/// The computation itself is the SDK's
/// [`arkret::identity::policy_digest`] (`ak.did.resolver_policy.v1`), not a
/// local snapshot: every repo that accepts bindings under the same
/// [`ResolverPolicy`] must derive the same key dimension, and a hand-written
/// `fail_mode` mapping (or a `Debug` rendering of it) silently forked that value
/// per repo. There are no deployment-local admissibility switches here beyond
/// the policy itself, so the bare `policy_digest` (no
/// [`arkret::identity::PolicyDigestInput`] extensions) is the complete input.
fn binding_policy_digest(policy: &ResolverPolicy) -> std::result::Result<Hash, String> {
    policy_digest(policy).map_err(|err| format!("binding policy digest failed: {err}"))
}

/// Why an ordinary (zero-network) binding lookup could not authenticate a
/// signature. Every variant is a fail-closed outcome: none of them may be
/// "fixed" by resolving once more on the ordinary path (§4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingLookupError {
    /// No accepted binding under this key. The caller decides whether a §4
    /// trigger applies; ordinary verification fails closed.
    Missing,
    /// A binding exists but is `deactivated` / `quarantined`.
    NotUsable { status: DidBindingStatus },
}

impl std::fmt::Display for BindingLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("no accepted DID binding"),
            Self::NotUsable { status } => {
                write!(formatter, "accepted DID binding is {status}")
            }
        }
    }
}

/// Read-only, **resolver-free** view over the accepted-binding store.
///
/// This is what ordinary per-signature verification is handed. It has no
/// resolver field, so the compiler — not a code-review convention — guarantees
/// that consuming it costs zero authority network calls.
#[derive(Clone)]
pub struct AcceptedDidBindings {
    store: Arc<dyn VerifiedDidBindingStore>,
    trust_domain: TrustDomainId,
    policy_digest: Hash,
}

impl std::fmt::Debug for AcceptedDidBindings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptedDidBindings")
            .field("trust_domain", &self.trust_domain)
            .field("policy_digest", &self.policy_digest)
            .finish_non_exhaustive()
    }
}

impl AcceptedDidBindings {
    /// The store key for one `(did, purpose, verification_method)` acceptance in
    /// this trust domain and under this policy revision.
    fn key(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: &DidUrl,
    ) -> VerifiedDidBindingKey {
        VerifiedDidBindingKey {
            did: did.clone(),
            trust_domain: self.trust_domain.clone(),
            purpose,
            policy_digest: self.policy_digest.clone(),
            verification_method: Some(verification_method.clone()),
        }
    }

    fn get(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, BindingLookupError> {
        let key = self.key(did, purpose, verification_method);
        let accepted = self
            .store
            .get(&key, now)
            .ok_or(BindingLookupError::Missing)?;
        if !accepted.binding().is_usable_for_ordinary_verification() {
            return Err(BindingLookupError::NotUsable {
                status: accepted.binding().status(),
            });
        }
        Ok(accepted)
    }

    /// The accepted **source service** binding backing the inbound RFC 9421
    /// HTTP Message Signature. It is the only purpose a bridge accepts, and a
    /// miss fails closed: there is no lookup to fall back on.
    pub fn source_service(
        &self,
        did: &Did,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, BindingLookupError> {
        self.get(did, DidBindingPurpose::Service, verification_method, now)
    }
}

/// The inbound binding store plus the acceptance entry points that write to it.
///
/// It owns no resolver and no way to obtain one, so every inbound request costs
/// zero DID authority network calls by construction rather than by convention.
pub struct DidAuthority {
    bindings: AcceptedDidBindings,
}

impl std::fmt::Debug for DidAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DidAuthority")
            .field("bindings", &self.bindings)
            .finish_non_exhaustive()
    }
}

impl DidAuthority {
    /// Build the inbound authority adapter and its accepted-binding store.
    pub fn new(trust_domain: TrustDomainId) -> Result<Self> {
        let policy_digest =
            binding_policy_digest(&inbound_binding_policy()).map_err(BridgeError::Runtime)?;
        Ok(Self {
            bindings: AcceptedDidBindings {
                store: Arc::new(InMemoryVerifiedDidBindingStore::new(BINDING_STORE_CAPACITY)),
                trust_domain,
                policy_digest,
            },
        })
    }

    /// The read-only view handed to ordinary verification.
    pub fn bindings(&self) -> &AcceptedDidBindings {
        &self.bindings
    }

    /// The trust domain every acceptance in this store is scoped to.
    ///
    /// The operator invalidation surface (`web.rs`) uses this to fail closed
    /// when a request names a *different* trust domain: §5.6's sweep is scoped,
    /// so a mismatched domain must be a rejected request, not a silent no-op.
    pub fn trust_domain(&self) -> &TrustDomainId {
        &self.bindings.trust_domain
    }

    /// Record the operator-configured HTTP-signature trust anchor as a
    /// `service`-purpose accepted binding.
    ///
    /// This is an acceptance, not a resolution: the key material comes from
    /// `arkret.trusted_verification_methods` in the bridge's own configuration,
    /// so it costs **zero** network calls and is strictly stronger than
    /// resolving the node's DID document at runtime.
    ///
    /// # Why `source_key_state_digest` is no longer folded into the evidence
    ///
    /// It used to be a `method` extension member of the SDK evidence envelope.
    /// The §5.2 [`DidBindingEvidenceReceipt`] that replaced that envelope is a closed
    /// three-member structure (`method` / `document_digest` / `method_proofs`)
    /// with no caller-supplied extension slot — deliberately, because "the
    /// caller supplies the evidence" is the shape the spec judges
    /// non-conformant.
    ///
    /// Nothing is lost. The key-state digest is a function of
    /// `public_key_multibase`, which is one of the two fields this document is
    /// built from, so `document_digest` already commits to the same key
    /// material: `web.rs::source_key_state_digest` digests the raw Ed25519
    /// public key bytes, and `public_key_multibase` is those same bytes in
    /// multibase form, so a different source key yields a different document,
    /// hence a different `document_digest`, hence a different
    /// `evidence_digest`. The binding still changes exactly when the source
    /// key state changes, which is what the extension member was there for.
    pub fn accept_configured_source_service_key(
        &self,
        verification_method: &DidUrl,
        public_key_multibase: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, String> {
        let did = verification_method_did(verification_method)?;
        let document = DidDocument::new(
            did.clone(),
            verification_method.as_str().to_owned(),
            public_key_multibase.to_owned(),
        );
        // A config-pinned anchor is not a resolution, so the method publishes no
        // proofs: `MethodEvidence::none()` is the normative degenerate form, not
        // a placeholder.
        let receipt = DidBindingEvidenceReceipt::new(
            did.method(),
            document_canonical_digest(&document)
                .map_err(|err| format!("source service document digest failed: {err}"))?,
            &MethodEvidence::none(),
        );
        let binding = VerifiedDidBinding::from_verified_document(
            &document,
            VerifiedDidBindingDocumentInput {
                trust_domain: self.bindings.trust_domain.clone(),
                purpose: DidBindingPurpose::Service,
                verification_method: Some(verification_method.clone()),
                history_head: None,
                version_id: None,
                limited_trust: LimitedTrust::for_proofless_method(None, None).record_for(),
                evidence_digest: receipt
                    .digest()
                    .map_err(|err| format!("source service evidence digest failed: {err}"))?,
                evidence_dependencies: receipt
                    .evidence_dependencies()
                    .map_err(|err| format!("source service evidence dependencies failed: {err}"))?,
                policy_digest: self.bindings.policy_digest.clone(),
                verified_at: now,
                // A config-pinned anchor never goes stale on its own: it can
                // only change by an operator editing the config and restarting.
                refresh_at: None,
                expires_at: None,
                status: DidBindingStatus::Active,
            },
        )
        .map_err(|err| format!("source service binding rejected: {err}"))?;
        let accepted = AcceptedDidBinding::new(binding, document, receipt)
            .map_err(|err| format!("source service binding/document pairing rejected: {err}"))?;
        self.bindings
            .store
            .accept(accepted.clone())
            .map_err(|err| format!("source service binding could not be stored: {err}"))?;
        Ok(accepted)
    }

    /// Answer the SDK [`arkret::AppletHandler`](arkret::AppletHandler)
    /// verification-method contract from the accepted-binding store.
    ///
    /// The SDK router calls this to authenticate an inbound push, so it lives
    /// here rather than on the handler. It is store-only: the operator-pinned
    /// trust anchors are accepted at startup, and a method that has no
    /// acceptance fails closed instead of triggering a lookup — §4's exclusion
    /// list gives a bridge no trigger that would justify one.
    pub fn service_verification_method(
        &self,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, String> {
        let did = verification_method_did(verification_method)?;
        self.bindings
            .source_service(&did, verification_method, now)
            .map_err(|error| {
                format!("no usable source service DID binding for `{verification_method}`: {error}")
            })
    }

    /// Drop every acceptance for `did` (§5: rotation / deactivation / witness
    /// fork / revocation MUST invalidate the affected bindings). Scoped to this
    /// bridge's trust domain so an unrelated domain is never touched.
    pub fn invalidate_did(&self, did: &Did) -> usize {
        self.bindings.store.invalidate(
            &BindingInvalidation::for_did(did.clone())
                .with_trust_domain(self.bindings.trust_domain.clone()),
        )
    }
}

/// The bare DID that controls `verification_method`.
///
/// `DidUrl` already guarantees a non-empty `#fragment` and rejects `?query`, so
/// this only has to split.
pub fn verification_method_did(verification_method: &DidUrl) -> std::result::Result<Did, String> {
    let (did, _) = verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| format!("verification method `{verification_method}` has no `#fragment`"))?;
    Did::new(did.to_owned())
        .map_err(|err| format!("verification method DID `{did}` is invalid: {err}"))
}

#[cfg(test)]
mod tests {
    use arkret::identity::public_key_material_from_binding;

    use super::*;

    fn authority() -> DidAuthority {
        DidAuthority::new(trust_domain()).expect("authority")
    }

    fn trust_domain() -> TrustDomainId {
        TrustDomainId::new("ak:trust_domain:bridge.example".to_owned()).expect("trust domain")
    }

    /// A **real** Ed25519 public key derived from `seed`.
    ///
    /// Not `[seed; 32]`: the SDK's `public_key_material_from_binding` decodes
    /// the published material into a `VerifyingKey`, so a fixture that is not a
    /// decompressible Edwards point is rejected at lookup time rather than at
    /// signature verification. That is the tighter behaviour and the fixtures
    /// follow it, exactly as the `web.rs` tests already did.
    fn public_key_bytes(seed: u8) -> [u8; 32] {
        arkret::Ed25519PayloadSigner::from_did_key_seed(
            [seed; 32],
            Did::new("did:webvh:z6mkfixture:seed.example".to_owned()).expect("did"),
            DidUrl::new("did:webvh:z6mkfixture:seed.example#key-1").expect("did url"),
        )
        .verifying_key()
        .to_bytes()
    }

    fn multibase(seed: u8) -> String {
        arkret::ed25519_pubkey_to_did_key_multibase(&public_key_bytes(seed))
    }

    /// §5 non-degeneracy gate, mirroring the SDK's
    /// `evidence_digest_is_never_the_bare_document_digest`.
    ///
    /// The bridge previously recorded either `f(did) + two constants` (which
    /// carried no method evidence at all) or the bare `source_key_state_digest`.
    /// Both are unrepresentable through the SDK evidence receipt; this test
    /// states the property the local repo relies on: the recorded value is not
    /// the document digest it commits to, and an auditor can recompute it from
    /// the retained receipt.
    #[test]
    fn accepted_evidence_is_a_recomputable_receipt_not_a_degenerate_digest() {
        let authority = authority();
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let key = multibase(7);
        let now = Utc::now();

        let accepted = authority
            .accept_configured_source_service_key(&vm, &key, now)
            .expect("service binding accepted");
        let binding = accepted.binding();

        // The degenerate `evidence_digest = document_digest` form stays
        // unreachable: the receipt digests `{kind, method, document_digest,
        // method_proofs}`, never the document digest alone.
        assert_ne!(binding.evidence_digest(), binding.document_digest());

        // "Auditable" means "recomputable": an auditor rebuilds the retained
        // receipt from the pinned document and gets the stored digest back.
        let recomputed = DidBindingEvidenceReceipt::new(
            binding.did().method(),
            document_canonical_digest(accepted.document()).expect("document digest"),
            &MethodEvidence::none(),
        );
        assert_eq!(&recomputed, accepted.evidence_receipt());
        assert_eq!(
            binding.evidence_digest(),
            &recomputed.digest().expect("evidence digest")
        );
        // A config-pinned anchor pins neither pin, and says so per pin rather
        // than omitting the record (§5.5).
        assert_eq!(
            binding.limited_trust(),
            LimitedTrust::for_proofless_method(None, None).record_for()
        );
    }

    /// A bridge never accepts a DID it was not configured with: there is no
    /// resolver to reach and `service_verification_method` fails closed.
    #[test]
    fn an_unconfigured_verification_method_fails_closed() {
        let authority = authority();
        let configured =
            DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let foreign = DidUrl::new("did:webvh:z6mkfixture:attacker.example#key-1").expect("did url");
        let now = Utc::now();

        authority
            .accept_configured_source_service_key(&configured, &multibase(7), now)
            .expect("service binding accepted");

        assert!(
            authority
                .service_verification_method(&configured, now)
                .is_ok()
        );
        assert!(
            authority
                .service_verification_method(&foreign, now)
                .is_err()
        );
    }

    #[test]
    fn accepted_binding_publishes_the_configured_key_without_a_resolver() {
        let authority = authority();
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let did = verification_method_did(&vm).expect("did");
        let key = multibase(9);
        let now = Utc::now();

        authority
            .accept_configured_source_service_key(&vm, &key, now)
            .expect("service binding accepted");
        let accepted = authority
            .bindings()
            .source_service(&did, &vm, now)
            .expect("binding");
        let material = public_key_material_from_binding(&accepted, &vm).expect("key material");
        assert_eq!(
            material.ed25519_bytes().expect("bytes"),
            public_key_bytes(9)
        );
    }

    #[test]
    fn rotating_the_configured_key_replaces_the_binding() {
        let authority = authority();
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let did = verification_method_did(&vm).expect("did");
        let now = Utc::now();

        let old = multibase(1);
        authority
            .accept_configured_source_service_key(&vm, &old, now)
            .expect("first acceptance");
        let new = multibase(2);
        authority
            .accept_configured_source_service_key(&vm, &new, now)
            .expect("rotated acceptance");

        let accepted = authority
            .bindings()
            .source_service(&did, &vm, now)
            .expect("binding");
        let material = public_key_material_from_binding(&accepted, &vm).expect("key material");
        assert_eq!(
            material.ed25519_bytes().expect("bytes"),
            public_key_bytes(2)
        );
    }

    #[test]
    fn invalidating_one_did_leaves_other_dids_accepted() {
        let authority = authority();
        let left = DidUrl::new("did:webvh:z6mkfixture:a.example#key-1").expect("did url");
        let right = DidUrl::new("did:webvh:z6mkfixture:b.example#key-1").expect("did url");
        let now = Utc::now();
        let key = multibase(3);

        for vm in [&left, &right] {
            authority
                .accept_configured_source_service_key(vm, &key, now)
                .expect("accepted");
        }

        let left_did = verification_method_did(&left).expect("did");
        let right_did = verification_method_did(&right).expect("did");
        assert_eq!(authority.invalidate_did(&left_did), 1);
        assert_eq!(
            authority.bindings().source_service(&left_did, &left, now),
            Err(BindingLookupError::Missing)
        );
        assert!(
            authority
                .bindings()
                .source_service(&right_did, &right, now)
                .is_ok()
        );
    }

    /// Source-level regression gate for the §6 layering rule (business reducers,
    /// projections, queries, UI, and routing code do not hold a general network resolver)
    /// and for the ruling that a bridge has **no** DID authority call site at
    /// all: inbound Event proof signer authority is carried by the source
    /// Arkret node, and the HTTP-signature anchor comes from configuration.
    ///
    /// A handler that grows its own resolver chain fails here rather than
    /// quietly reintroducing per-request DID resolution.
    #[test]
    fn the_runtime_constructs_no_network_did_resolver() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sites = Vec::new();
        for entry in std::fs::read_dir(&src).expect("runtime src directory") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file");
            // Only production code is gated; this very test names the types.
            let text = match text.find(
                "
#[cfg(test)]
",
            ) {
                Some(offset) => &text[..offset],
                None => &text[..],
            };
            for (index, line) in text.lines().enumerate() {
                // Skip doc comments: the module docs name the type on purpose.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains("CompositeDidResolver::new(")
                    || line.contains("HttpDidResolver::with_policy(")
                    || line.contains("resolve_and_verify_binding(")
                {
                    sites.push(format!(
                        "{}:{}",
                        path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                        index + 1
                    ));
                }
            }
        }
        assert!(
            sites.is_empty(),
            "a bridge has no registered DID authority call site, so it must              build no resolver chain at all; found: {sites:?}"
        );
    }

    #[test]
    fn verification_method_did_rejects_a_foreign_fragmentless_value() {
        // `DidUrl` already rejects bare DIDs at construction, so the only way
        // into this helper is with a fragment.
        assert!(DidUrl::new("did:webvh:z6mkfixture:server.example").is_err());
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        assert_eq!(
            verification_method_did(&vm).expect("did").as_str(),
            "did:webvh:z6mkfixture:server.example"
        );
    }
}

use arkret::DidBindingEvidenceReceiptExt;
