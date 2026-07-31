//! Accepted DID bindings for the inbound applet transaction path
//! (`identity/did-usage-and-verification.md` §3 / §4 / §5 / §6).
//!
//! # Why this module exists
//!
//! Before DID-P1-B01 the inbound `POST /_arkret/edge/applet/transactions`
//! handler held one `Arc<CompositeDidResolver>` and re-resolved **every** Event
//! proof's `verification_method` on **every** transaction. That violates §3
//! ("验证签名不等于重新验证 DID") and §6 ("业务 reducer、projection、query、UI
//! 与 routing 代码只消费 verified binding 或 accepted auth-state，不直接持有
//! 通用网络 resolver").
//!
//! The split here is a **type-level** one, not a convention:
//!
//! | type | holds a resolver? | who uses it |
//! | --- | --- | --- |
//! | [`AcceptedDidBindings`] | no — structurally impossible | ordinary per-signature verification |
//! | [`DidAuthority`] | yes, in a private field | the §4 authority triggers only |
//!
//! `AcceptedDidBindings` has no resolver field and no way to obtain one, so
//! `crate::web::verify_transaction_events` — which takes exactly that type —
//! cannot make a network call even by mistake.
//!
//! # Purpose isolation (DID-P1-B01)
//!
//! The HTTP Message Signature of the pushing Arkret node and the Event proofs it
//! carries are authenticated against **different** bindings that can never
//! substitute for each other, because [`DidBindingPurpose`] is part of the store
//! key:
//!
//! | material | purpose | DID | source of the acceptance |
//! | --- | --- | --- | --- |
//! | RFC 9421 HTTP signature | [`DidBindingPurpose::Service`] | `arkret.trusted_server_did` | [`DidAuthority::accept_configured_source_service_key`] (config trust anchor, zero network) |
//! | Event `proofs[]` | [`DidBindingPurpose::Principal`] | the Event's `executed_by` / `actor_id` | [`DidAuthority::accept_event_signer`] (§4 row 1/3, exactly one resolve) |
//!
//! A `Service` acceptance for the node DID therefore cannot authorize an Event
//! proof, and an Event-signer acceptance cannot authorize the HTTP signature,
//! even when the two DIDs coincide.
//!
//! ## Why `Principal` and not `DeviceSigner` / `AgentSigner`
//!
//! What a bridge actually verifies about an Event proof is that
//! `proof.verification_method` is published by the *actor's own* DID document
//! and that its DID part equals `executed_by` / `actor_id`. Bridges never sees
//! device-authorization or agent-signer-epoch evidence, so claiming
//! `DeviceSigner` / `AgentSigner` would record an acceptance it did not make.
//! §5 requires the binding to state what was actually verified, so the honest
//! closed purpose is `Principal` (actor identity control).
//!
//! # Version / epoch dimension
//!
//! `VerifiedDidBindingKey.version_id` is `None` for every binding built here,
//! with [`LimitedTrustReason::MethodHasNeitherHistoryNorVersion`] recorded as
//! §5 demands. Two independent reasons:
//!
//! 1. **No Applet registration epoch is reachable from a bridge.** `registration_epoch`
//!    (`applet-schema.md` §1.0.1) is computed over an `AppletPackage` transcript held by the Arkret
//!    node that installed the applet. A bridge never builds, receives or stores an `AppletPackage`,
//!    `AppletTransactionRequestBody` carries no epoch, and there is no config field for one. For
//!    the node → applet direction `applet-integration.md` §12 names the anchor material as "Arkret
//!    node 方向的 source service DID key-state evidence" — which is exactly
//!    `VerifiedAppletHttpRequest::source_key_state_digest`, already recorded in the idempotency
//!    anchor. That digest enters the binding's `evidence_digest` as the
//!    `method.source_key_state_digest` member of the SDK [`arkret::identity::EvidenceEnvelope`],
//!    alongside the pinned `document_digest` and the `policy_digest`. Converging on the SDK
//!    envelope did not change this conclusion: the envelope gives the evidence a recomputable
//!    shape, it does not make a `registration_epoch` reachable.
//! 2. **The resolver returns no version evidence.** `CompositeDidResolver::resolve_did` yields a
//!    bare `DidDocument`; no `history_head` and no `version_id` are available to pin, and the
//!    envelope's `method_proofs` is therefore empty for every resolve-backed acceptance.
//!
//! Freshness is therefore carried by `refresh_after` / `expires_at` plus the
//! `verification_method` key dimension, and rotation is handled by explicit
//! [`DidAuthority::invalidate_did`] (§4 row 7 "收到 rotation / deactivation /
//! witness fork / policy-change invalidation").

use std::sync::Arc;

use arkret::identity::{
    AcceptedDidBinding, BindingAcceptanceTerms, BindingInvalidation,
    DeferredEvidenceResolveRequest, DidBindingPurpose, DidBindingStatus, DidDocument,
    EvidenceEnvelope, FreshnessRequirement, InMemoryVerifiedDidBindingStore, LimitedTrustReason,
    ResolverFailMode, ResolverPolicy, VerifiedDidBinding, VerifiedDidBindingDocumentInput,
    VerifiedDidBindingKey, VerifiedDidBindingStore, policy_digest,
    resolve_and_verify_binding_with_evidence,
};
use arkret::{
    CompositeDidResolver, Did, DidKeyResolver, DidResolver, Hash, HttpDidResolver,
    TypedTrustDomainId,
};
use arkret_wire::DidUrl;
use chrono::{DateTime, Duration, Utc};

use crate::error::{BridgeError, Result};

/// Background-refresh point for an accepted inbound binding. Crossing it only
/// marks the binding `stale`; §5 forbids turning that into a live resolution on
/// an ordinary request, so the ordinary path keeps consuming it.
const BINDING_REFRESH_AFTER_SECS: i64 = 3600;
/// Hard-expiry point. Past it the entry no longer exists for readers, so the
/// next transaction from that signer re-enters the authority path exactly once
/// (§4, last trigger row: "显式要求的 freshness 已过期").
const BINDING_HARD_EXPIRY_SECS: i64 = 24 * 3600;

/// Upper bound on distinct accepted bindings held in memory. Inbound pushes
/// come from one trusted node but may carry Events from many actors, so the
/// store is bounded (deterministic oldest-`verified_at` eviction) rather than
/// unbounded.
const BINDING_STORE_CAPACITY: usize = 4096;

/// The resolver policy every inbound DID acceptance is made under.
///
/// Workspace-wide rule: actor / service identities are `did:webvh` only
/// (`did:web` is not an accepted alias); `did:key` stays for bare
/// verification-method keys.
fn inbound_resolver_policy() -> ResolverPolicy {
    ResolverPolicy {
        allowed_methods: vec!["did:key:".to_owned(), "did:webvh:".to_owned()],
        fail_mode: ResolverFailMode::FailClosed,
        ..ResolverPolicy::default()
    }
}

/// Canonical digest of the effective resolver policy.
///
/// This is the `policy_digest` dimension of [`VerifiedDidBindingKey`]: a policy
/// revision changes the digest, which changes the key, so a binding accepted
/// under an older policy is never silently reused (§5, "Realm resolver policy
/// 变化 MUST 使受影响 binding 失效").
///
/// The computation itself is the SDK's
/// [`arkret::identity::policy_digest`] (`ak.did.resolver_policy.v1`), not a
/// local snapshot: every repo that accepts bindings under the same
/// [`ResolverPolicy`] must derive the same key dimension, and a hand-written
/// `fail_mode` mapping (or a `Debug` rendering of it) silently forked that value
/// per repo. There are no deployment-local admissibility switches here beyond
/// the policy itself — `DidAuthority::new` hands exactly this policy to both
/// `CompositeDidResolver` and `HttpDidResolver` — so the bare
/// `policy_digest` (no [`arkret::identity::PolicyDigestInput`] extensions) is
/// the complete input.
fn resolver_policy_digest(policy: &ResolverPolicy) -> std::result::Result<Hash, String> {
    policy_digest(policy).map_err(|err| format!("resolver policy digest failed: {err}"))
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
    trust_domain: TypedTrustDomainId,
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
            // See the module docs: no history head / version evidence is
            // reachable on the inbound applet path.
            version_id: None,
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
    /// HTTP Message Signature. Never usable for an Event proof.
    pub fn source_service(
        &self,
        did: &Did,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, BindingLookupError> {
        self.get(did, DidBindingPurpose::Service, verification_method, now)
    }

    /// The accepted **Event signer** binding for one `proof.verification_method`.
    /// Never usable for the HTTP Message Signature.
    pub fn event_signer(
        &self,
        did: &Did,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, BindingLookupError> {
        self.get(did, DidBindingPurpose::Principal, verification_method, now)
    }

    /// Whether an Event-signer acceptance already exists (zero network).
    pub fn has_event_signer(
        &self,
        did: &Did,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> bool {
        self.event_signer(did, verification_method, now).is_ok()
    }
}

/// The **only** type on the inbound path that owns a network DID resolver.
///
/// Everything reachable from a handler is either [`AcceptedDidBindings`] (no
/// resolver) or one of the explicitly named §4 authority entry points below.
/// The `resolver` field is private and no accessor returns it.
pub struct DidAuthority {
    resolver: Arc<dyn DidResolver + Send + Sync>,
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
    pub fn new(trust_domain: TypedTrustDomainId) -> Result<Self> {
        let policy = inbound_resolver_policy();
        let mut resolver = CompositeDidResolver::new().with_policy(policy.clone());
        resolver.push(DidKeyResolver::new());
        resolver.push(HttpDidResolver::with_policy(policy)?);
        Self::with_resolver(trust_domain, Arc::new(resolver))
    }

    /// Same, with a caller-supplied resolver. Used by the DID-P1-B02 tests to
    /// substitute a counting spy and assert that ordinary transactions add zero
    /// authority network calls.
    pub fn with_resolver(
        trust_domain: TypedTrustDomainId,
        resolver: Arc<dyn DidResolver + Send + Sync>,
    ) -> Result<Self> {
        let policy_digest =
            resolver_policy_digest(&inbound_resolver_policy()).map_err(BridgeError::Runtime)?;
        Ok(Self {
            resolver,
            bindings: AcceptedDidBindings {
                store: Arc::new(InMemoryVerifiedDidBindingStore::new(BINDING_STORE_CAPACITY)),
                trust_domain,
                policy_digest,
            },
        })
    }

    /// The resolver-free view handed to ordinary verification.
    pub fn bindings(&self) -> &AcceptedDidBindings {
        &self.bindings
    }

    /// Record the operator-configured HTTP-signature trust anchor as a
    /// `service`-purpose accepted binding.
    ///
    /// This is an acceptance, not a resolution: the key material comes from
    /// `arkret.trusted_verification_methods` in the bridge's own configuration,
    /// so it costs **zero** network calls and is strictly stronger than
    /// resolving the node's DID document at runtime. `key_state_digest` is the
    /// `source_key_state_digest` the idempotency anchor already records; it
    /// enters the binding's `evidence_digest` as a **member of the SDK evidence
    /// envelope** (`{document_digest, method_proofs: [], policy_digest,
    /// method: {source_key_state_digest}}`), not as the digest itself, so the
    /// recorded evidence commits to the pinned document and the policy as well
    /// (see the module docs on why the key-state digest stands in for an Applet
    /// `registration_epoch`).
    pub fn accept_configured_source_service_key(
        &self,
        verification_method: &DidUrl,
        public_key_multibase: &str,
        key_state_digest: &Hash,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, String> {
        let did = verification_method_did(verification_method)?;
        let document = DidDocument::new(
            did.clone(),
            verification_method.as_str().to_owned(),
            public_key_multibase.to_owned(),
        );
        let evidence_digest =
            EvidenceEnvelope::for_document(&document, self.bindings.policy_digest.clone())
                .map_err(|err| format!("source service evidence envelope failed: {err}"))?
                .with_extension("source_key_state_digest", key_state_digest.as_str())
                .digest()
                .map_err(|err| format!("source service evidence digest failed: {err}"))?;
        let binding = VerifiedDidBinding::from_verified_document(
            &document,
            VerifiedDidBindingDocumentInput {
                trust_domain: self.bindings.trust_domain.clone(),
                purpose: DidBindingPurpose::Service,
                verification_method: Some(verification_method.clone()),
                history_head: None,
                version_id: None,
                limited_trust: Some(LimitedTrustReason::MethodHasNeitherHistoryNorVersion),
                evidence_digest,
                policy_digest: self.bindings.policy_digest.clone(),
                verified_at: now,
                // A config-pinned anchor never goes stale on its own: it can
                // only change by an operator editing the config and restarting.
                refresh_after: None,
                expires_at: None,
                status: DidBindingStatus::Active,
            },
        )
        .map_err(|err| format!("source service binding rejected: {err}"))?;
        let accepted = AcceptedDidBinding::new(binding, document)
            .map_err(|err| format!("source service binding/document pairing rejected: {err}"))?;
        self.bindings
            .store
            .accept(accepted.clone())
            .map_err(|err| format!("source service binding could not be stored: {err}"))?;
        Ok(accepted)
    }

    /// Establish or refresh an **Event signer** binding — the only inbound path
    /// that reaches the network.
    ///
    /// `did-usage-and-verification.md` §4 triggers this call site can name:
    ///
    /// - row 1: a DID that this trust domain has not accepted before crosses the boundary;
    /// - row 3: a `verification_method` not yet accepted for an already-known DID;
    /// - row 7: a received rotation / deactivation / policy-change invalidation, or an expired
    ///   freshness window.
    ///
    /// Callers MUST have checked [`AcceptedDidBindings::has_event_signer`]
    /// first, so a warm binding costs zero calls.
    /// `resolve_and_verify_binding_with_evidence` re-checks the store itself and
    /// then resolves **exactly once**; on a store hit the evidence closure is
    /// not called, so a cached acceptance keeps the evidence it was made under.
    pub fn accept_event_signer(
        &self,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, String> {
        let did = verification_method_did(verification_method)?;
        let request = DeferredEvidenceResolveRequest {
            did,
            trust_domain: self.bindings.trust_domain.clone(),
            purpose: DidBindingPurpose::Principal,
            policy_digest: self.bindings.policy_digest.clone(),
            verification_method: Some(verification_method.clone()),
            // Establishing a *new* acceptance: an existing entry may only be
            // reused when it is still inside its refresh window.
            freshness: FreshnessRequirement::fresh_within(Duration::seconds(
                BINDING_HARD_EXPIRY_SECS,
            )),
            acceptance: self.resolved_document_acceptance_terms(),
        };
        self.resolve_with_document_evidence(&request, now)
    }

    /// Resolve one verification method for the SDK
    /// [`arkret::AppletHandler`](arkret::AppletHandler) contract.
    ///
    /// This is an authority surface by definition — the SDK router calls it to
    /// authenticate an inbound push — so it lives here and not on the handler.
    /// It is store-first: a warm `service` binding answers without a network
    /// call.
    pub fn service_verification_method(
        &self,
        verification_method: &DidUrl,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, String> {
        let did = verification_method_did(verification_method)?;
        if let Ok(accepted) = self.bindings.source_service(&did, verification_method, now) {
            return Ok(accepted);
        }
        let request = DeferredEvidenceResolveRequest {
            did,
            trust_domain: self.bindings.trust_domain.clone(),
            purpose: DidBindingPurpose::Service,
            policy_digest: self.bindings.policy_digest.clone(),
            verification_method: Some(verification_method.clone()),
            freshness: FreshnessRequirement::fresh_within(Duration::seconds(
                BINDING_HARD_EXPIRY_SECS,
            )),
            acceptance: self.resolved_document_acceptance_terms(),
        };
        self.resolve_with_document_evidence(&request, now)
    }

    /// Acceptance terms shared by both resolve-backed paths.
    ///
    /// `version_id` / `history_head` stay `None` with an explicit limited-trust
    /// reason: see the module docs — the resolver chain returns a bare
    /// `DidDocument` and no Applet `registration_epoch` is reachable from a
    /// bridge.
    fn resolved_document_acceptance_terms(&self) -> BindingAcceptanceTerms {
        BindingAcceptanceTerms {
            history_head: None,
            version_id: None,
            limited_trust: Some(LimitedTrustReason::MethodHasNeitherHistoryNorVersion),
            refresh_interval: Some(Duration::seconds(BINDING_REFRESH_AFTER_SECS)),
            hard_expiry: Some(Duration::seconds(BINDING_HARD_EXPIRY_SECS)),
        }
    }

    /// Resolve once and seal the acceptance with an evidence digest computed
    /// over the **resolved** document.
    ///
    /// The evidence is the SDK envelope `{version, document_digest,
    /// method_proofs: [], policy_digest, method: {}}` — a commitment to the
    /// exact document this acceptance rests on *and* to the resolver policy it
    /// was admitted under. `method_proofs` is empty because
    /// `CompositeDidResolver::resolve_did` returns a bare `DidDocument`: no
    /// webvh log head, witness set or controller proof bundle is exposed to
    /// digest. Recording an empty proof set is the honest statement (§5); it is
    /// still strictly stronger than the digest it replaces, because a policy
    /// change now changes the evidence too, and the value can be recomputed by
    /// an auditor from the pinned document.
    fn resolve_with_document_evidence(
        &self,
        request: &DeferredEvidenceResolveRequest,
        now: DateTime<Utc>,
    ) -> std::result::Result<AcceptedDidBinding, String> {
        let policy_digest = self.bindings.policy_digest.clone();
        let did = request.did.clone();
        resolve_and_verify_binding_with_evidence(
            self.resolver.as_ref(),
            self.bindings.store.as_ref(),
            request,
            move |document| Ok(EvidenceEnvelope::for_document(document, policy_digest)?.digest()?),
            now,
        )
        .map_err(|err| format!("DID authority verification failed for `{did}`: {err}"))
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

    /// Drop the acceptance for one concrete verification method (key rotation).
    pub fn invalidate_verification_method(&self, verification_method: &DidUrl) -> usize {
        self.bindings.store.invalidate(
            &BindingInvalidation::for_verification_method(verification_method.clone())
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

    /// A resolver that never answers. Every test in this module asserts a
    /// property of the *accepted binding* layer, so reaching this type at all
    /// would already be the bug.
    #[derive(Debug)]
    struct NeverResolvingDidResolver;

    impl DidResolver for NeverResolvingDidResolver {
        fn supports(&self, _did: &Did) -> bool {
            true
        }

        fn resolve_did(
            &self,
            did: &Did,
        ) -> std::result::Result<DidDocument, arkret::identity::IdentityError> {
            panic!("the accepted-binding path must never resolve `{did}`");
        }
    }

    fn authority() -> DidAuthority {
        DidAuthority::with_resolver(trust_domain(), Arc::new(NeverResolvingDidResolver))
            .expect("authority")
    }

    fn trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:bridge.example".to_owned()).expect("trust domain")
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

    fn key_state(multibase: &str) -> Hash {
        Hash::new(arkret::canonical::canonical_digest(multibase.as_bytes())).expect("hash")
    }

    /// A resolver that serves one prepared document, so an acceptance can be
    /// made for documents this module cannot build through the config path.
    #[derive(Debug)]
    struct OneDocumentDidResolver(DidDocument);

    impl DidResolver for OneDocumentDidResolver {
        fn supports(&self, _did: &Did) -> bool {
            true
        }

        fn resolve_did(
            &self,
            did: &Did,
        ) -> std::result::Result<DidDocument, arkret::identity::IdentityError> {
            if did == &self.0.id {
                Ok(self.0.clone())
            } else {
                Err(arkret::identity::IdentityError::Protocol(format!(
                    "unknown DID `{did}`"
                )))
            }
        }
    }

    #[test]
    fn pinned_documents_with_relative_verification_method_ids_still_resolve_their_key() {
        // DID Core 1.0 §3.1 allows `verificationMethod[].id` to be relative, and
        // `DidDocument` keeps the wire spelling verbatim. Both `#key-1` and the
        // absolute form must find the same key.
        let did = Did::new("did:webvh:z6mkfixture:relative.example".to_owned()).expect("did");
        let vm = DidUrl::new(format!("{did}#key-1")).expect("did url");
        let document = DidDocument::new(did.clone(), "#key-1", multibase(5));
        let authority =
            DidAuthority::with_resolver(trust_domain(), Arc::new(OneDocumentDidResolver(document)))
                .expect("authority");
        let now = Utc::now();

        let accepted = authority
            .accept_event_signer(&vm, now)
            .expect("event signer accepted");
        let material = public_key_material_from_binding(&accepted, &vm).expect("key material");
        assert_eq!(
            material.ed25519_bytes().expect("bytes"),
            public_key_bytes(5)
        );
    }

    /// §5 non-degeneracy gate, mirroring the SDK's
    /// `evidence_digest_is_never_the_bare_document_digest`.
    ///
    /// The bridge previously recorded either `f(did) + two constants` (which
    /// carried no method evidence at all) or the bare `source_key_state_digest`.
    /// Both are unrepresentable through the SDK envelope; this test states the
    /// property the local repo relies on: the recorded value is neither of the
    /// digests it commits to, and an auditor can recompute it.
    #[test]
    fn accepted_evidence_is_a_recomputable_envelope_not_a_degenerate_digest() {
        let authority = authority();
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let key = multibase(7);
        let anchor = key_state(&key);
        let now = Utc::now();

        let accepted = authority
            .accept_configured_source_service_key(&vm, &key, &anchor, now)
            .expect("service binding accepted");
        let binding = accepted.binding();

        assert_ne!(binding.evidence_digest(), binding.document_digest());
        assert_ne!(binding.evidence_digest(), &anchor);

        let recomputed =
            EvidenceEnvelope::for_document(accepted.document(), binding.policy_digest().clone())
                .expect("envelope")
                .with_extension("source_key_state_digest", anchor.as_str())
                .digest()
                .expect("evidence digest");
        assert_eq!(binding.evidence_digest(), &recomputed);
    }

    #[test]
    fn source_service_and_event_signer_bindings_never_substitute_for_each_other() {
        let authority = authority();
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let did = verification_method_did(&vm).expect("did");
        let key = multibase(7);
        let now = Utc::now();

        authority
            .accept_configured_source_service_key(&vm, &key, &key_state(&key), now)
            .expect("service binding accepted");

        // The service acceptance answers the HTTP-signature lookup...
        assert!(authority.bindings().source_service(&did, &vm, now).is_ok());
        // ...and is invisible to the Event-proof lookup, which is keyed by a
        // different purpose even though the DID and the key are identical.
        assert_eq!(
            authority.bindings().event_signer(&did, &vm, now),
            Err(BindingLookupError::Missing)
        );
        assert!(!authority.bindings().has_event_signer(&did, &vm, now));
    }

    #[test]
    fn accepted_binding_publishes_the_configured_key_without_a_resolver() {
        let authority = authority();
        let vm = DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").expect("did url");
        let did = verification_method_did(&vm).expect("did");
        let key = multibase(9);
        let now = Utc::now();

        authority
            .accept_configured_source_service_key(&vm, &key, &key_state(&key), now)
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
            .accept_configured_source_service_key(&vm, &old, &key_state(&old), now)
            .expect("first acceptance");
        let new = multibase(2);
        authority
            .accept_configured_source_service_key(&vm, &new, &key_state(&new), now)
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
                .accept_configured_source_service_key(vm, &key, &key_state(&key), now)
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

    /// Source-level regression gate for the §6 layering rule ("业务 reducer、
    /// projection、query、UI 与 routing 代码 … 不直接持有通用网络 resolver").
    ///
    /// The general-purpose network resolver chain may be constructed in exactly
    /// one place — [`DidAuthority::new`]. A handler that grows its own
    /// `CompositeDidResolver` fails this test rather than quietly reintroducing
    /// per-request DID resolution.
    #[test]
    fn the_network_resolver_is_constructed_in_exactly_one_place() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sites = Vec::new();
        for entry in std::fs::read_dir(&src).expect("runtime src directory") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file");
            // Only production code is gated; this very test names the types.
            let text = match text.find("\n#[cfg(test)]\n") {
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
                {
                    sites.push(format!(
                        "{}:{}",
                        path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                        index + 1
                    ));
                }
            }
        }
        assert_eq!(
            sites.len(),
            2,
            "expected exactly one resolver-chain construction site \
             (`CompositeDidResolver::new` + `HttpDidResolver::with_policy` in \
             did_binding.rs), found: {sites:?}"
        );
        assert!(
            sites.iter().all(|site| site.starts_with("did_binding.rs:")),
            "the network resolver must only be built inside the DID authority \
             adapter, found: {sites:?}"
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
