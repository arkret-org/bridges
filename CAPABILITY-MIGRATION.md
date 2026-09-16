# Authority-Commit Capability Migration

This checklist separates protocol replacement from product removal. A product
capability stays present unless its specification was explicitly removed. A
module may be deleted only when every responsibility in it belongs exclusively
to the superseded distributed-consistency mechanism. A mixed module is split, not
deleted.

## Protocol invariants

- [x] Producer `Event` carries no predecessor, ordering, basis, Seal, or Cell field.
- [x] Every shared durable Realm Event is submitted to the current governance
  Station, which returns the authority-signed `RealmCommit`.
- [x] `EventCommitSubmission { event }` is the only Event submission DTO on the
  outbound edge.
- [x] Only `RealmCommit` carries `previous_commit_ref`, and only within one stream.
- [x] Realm, each Circle and each Sidecar are independent commit streams. Nothing
  in this repository merges them or compares positions across them.
- [x] The bridge retains the exact `CommittedEventRef` of an accepted publication
  and never re-derives it.
- [x] An Applet-managed actor unit keeps its producer boundary: a governance
  Station may authorize and commit those Events but can never produce them.

## Product capabilities preserved

| Capability | Implementation | Tests |
|---|---|---|
| Generic bridge contract, inbound pump, Signal forwarding, dead-letter replay | `crates/runtime/src/app.rs` | covered through `crates/runtime/src/web.rs` route tests |
| Authority-commit protocol core: submission queue, stream cursor book, join bootstrap, handoff validation, producer/managed-actor proof verification | `crates/runtime/src/authority.rs` | `authority::tests` (5) |
| Outbound edge: intents, authoring, signing, Station submission, blob upload/download, bridge-error events | `crates/runtime/src/arkret_edge.rs` | `arkret_edge::tests` (7) |
| Durable publication journal: frozen signed bytes, atomic settled answer, committed reference, restart replay set | `crates/runtime/src/authoring.rs` | `arkret_edge::tests`, `authoring::database_tests` |
| Single-process crash-safe journal backend (redb) | `crates/runtime/src/file_authoring_store.rs` | `file_authoring_store::tests` |
| Diesel pool, migrations, transaction idempotency, event dedup, replay guard, token cache, dead letters | `crates/runtime/src/db.rs`, `crates/runtime/migrations/` | `db::tests` |
| HTTP service: health, metrics, applet edge routes, HTTP Message Signature verification, admin DID-binding invalidation, rate limiting, plane isolation | `crates/runtime/src/web.rs` | `web::tests` |
| Accepted DID bindings and the operator invalidation command | `crates/runtime/src/did_binding.rs` | `did_binding::tests`, `web::tests` |
| Per-conversation ordering queue | `crates/runtime/src/queue.rs` | exercised by `app.rs` consumers |
| Configuration loading, env/file references, logging, telemetry, backoff, blocking helper | `crates/runtime/src/config.rs`, `logging.rs`, `telemetry.rs`, `backoff.rs`, `blocking.rs` | `config::tests` |
| Channel/message/user mapping store and the applet actor/realm resolver | `crates/messaging/src/store.rs`, `models.rs`, `schema.rs`, `crates/messaging/migrations/` | `store::tests` |
| Ghost provisioning, `external_ref` provenance, portal strand acquisition | `crates/messaging/src/ghost.rs` | `ghost::provider_tests`, `messaging::tests` |
| Applet-managed identity generation, encryption at rest, authoring ledger, author endpoint | `crates/messaging/src/managed_actor_authoring.rs` | `store::tests::managed_actor_ledger_replays_exact_bundle_and_keeps_request_generations` |
| Message content mapping, media forwarding, vendor tokens, webhook helpers, adapter traits | `crates/messaging/src/lib.rs`, `content.rs`, `media.rs`, `token.rs`, `webhook.rs`, `types.rs` | `messaging::tests`, `webhook::tests` |
| 14 platform adapters | `crates/{discord,telegram,slack,feishu,wechat,dingtalk,zulip,whatsapp,line,qq,googlechat,imessage,messenger,teams}` | per-adapter unit tests (55) |

## Removed as complete old-protocol units

Each entry below was removed because every responsibility in it belonged to the
superseded mechanism, and the authority-commit protocol has no object for it to
produce or consume.

- `ArkretEdge::next_hlc`, the per-Realm `HlcGenerator` cache and its node-id
  derivation. An Event has no HLC; order is the Station's stream position.
- `ArkretEdge::realm_authoring_basis`. It resolved a Seal frontier leaf and
  returned a `SealBasis`/`SealId` pair. Seal is removed; Station admission plus
  an authority-signed commit replaces it.
- `ArkretEdge::submit_initial` / `submit_initial_with_policy` and the
  `EventInitialSubmission` / `ProofAuthenticatedPublication` wrapper handling.
  `EventCommitSubmission` is the only submission DTO, so the wrapper has no shape
  to validate.
- `ArkretEdge::submit_bridge_error_with_auth_context` and the
  `authority_digest_suite` helper. Both existed to carry an `AuthContext` whose
  `authority_refs` were Seal ids; the digest suite is now the producer's own.
- The CBS effect-plane guard (`classify_intent_execution` /
  `CbsEffectPlane::Control`). CBS is removed; there is no ordinary/control plane
  split for a bridge to enforce.
- `authoring.rs` frontier machinery: `ScopeJournal`, `Candidate`, the actor-seq
  sibling bounds, `merge_frontier`, `accepted_frontier`, and the head-CAS loop
  (`AuthoringJournal::load` / `cas`). These existed only to position an Event on
  an actor chain and to merge peer-observed frontiers. The journal now stores one
  immutable publication per stable operation id plus its settled answer, and the
  sibling-bucket test that enforced the actor-seq bounds went with them.
- `ArkretConfig::ordinary_authoring_contexts`. It retained a per-Realm
  `AuthContext` basis for local authoring; authority now comes from the Station's
  commit, so a locally retained basis would be a second, unverifiable source.
- `ArkretConfig::signer_resolution_evidence_ref`. `ProducerEventProof` no longer
  carries signer resolution evidence, and `sign_event` no longer accepts it.
- The `ordinary_authoring` table name. "Ordinary" was CBS-plane vocabulary; the
  table is `authoring_journal` in both the SQL migration and the redb backend.

## Mixed modules that were split, not deleted

- `crates/runtime/src/arkret_edge.rs`: the intent/authoring/signing/blob/inbound
  surfaces stayed; only the HLC, actor-chain, Seal-basis and initial-publication
  seams were replaced by Station submission.
- `crates/runtime/src/authoring.rs`: exactly-once outbound delivery, immutable
  frozen bytes, poison-on-storage-failure and restart replay stayed; the frontier
  head and candidate bookkeeping were replaced by a per-operation record carrying
  the exact committed reference.
- `crates/runtime/src/web.rs`: the whole HTTP surface stayed. The authoring
  completion boundary check moved from the removed
  `AppletManagedActorAuthoringResult::validate_delivery_binding` /
  `validate_bindings` to a local composition of SDK validators
  (`validate_authoring_completion`), which additionally requires that the
  completion reports a Realm-stream commit rather than a Circle or Sidecar one.
- `crates/messaging/src/ghost.rs`: portal strand acquisition stayed. Its §10.1
  "earliest effective order" idempotency rule moved from an HLC comparison over a
  history read to the first match in an ascending scan of the Realm's own commit
  stream (`scan_commit_stream`), which is the order the Station signed.
- `crates/messaging/src/lib.rs` and `crates/messaging/src/store.rs`: the mapping
  tables kept their shape. `profile_event_ref` and `accountability_grant_ref` now
  store the whole canonical `CommittedEventRef` instead of a bare event id, so the
  stream coordinate of a provisioning fact is not silently dropped.
- `crates/runtime/migrations/00000000000001_runtime_initial`: all product tables
  were retained; only the journal table name changed. No protocol-only table
  existed in this repository, so none was dropped.

## Open blocker: Applet-managed actor bundle authoring

`ManagedActorAuthoringService::build_ghost_bundle` fails closed and every other
part of that capability (identity generation, encrypted key custody, the
authoring ledger, the `managed-actors/author` endpoint, the
`GhostProvisionRequestProvider` wiring) is intact and durable.

The reason is an SDK gap, not a bridge decision:

- `extensions/applet-integration.md` §9.1 defines the managed-actor creation unit
  as four cross-bound Events plus one aggregate proof, and
  `identity/key-management.md` §3.6.3 requires the unified `arkret-rust-sdk`
  authoring API to produce such a unit.
- `arkret-rust-sdk` currently exposes only the verifying half:
  `AppletManagedActorAuthoringRequest::sign_ghost` (Station side) and
  `AppletManagedActorAuthoringBundle::validate_bindings` (receiving side). The
  producer-side constructor that used to exist
  (`author_applet_managed_actor_bundle` with
  `AppletManagedActorBundleAuthoringInput`) is gone with no replacement.
- Hand-rolling the unit here would put the §9.1 cross-binding rules in two places
  and let them drift from the verifier, so this repository does not do it.

Unblocking requires a producer-side bundle authoring API in `arkret-rust-sdk`.
Until then a first-seen external user cannot be materialized as a Ghost actor.

## Verification gates

- [x] `cargo +nightly fmt` (bridges only; `--all` reaches into the sibling SDK
  checkout and must not be used for a write run).
- [x] `cargo check --workspace --all-features` and `--all-targets`.
- [x] `cargo test --workspace --all-features --no-fail-fast`: 161 passed,
  0 failed, 2 ignored (one is the explicit journal growth benchmark, one is a
  doc example).
- [x] `cargo clippy --workspace --all-features --all-targets`: clean.
- [x] `bash scripts/deletion_gate.sh`: every forbidden protocol identifier is at
  a zero baseline.
