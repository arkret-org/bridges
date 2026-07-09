CREATE TABLE IF NOT EXISTS transaction_idempotency (
    operation_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    source_service_did TEXT NOT NULL,
    destination_service_did TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    source_signature_anchor TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (
        operation_id,
        direction,
        source_service_did,
        destination_service_did,
        idempotency_key
    ));

CREATE TABLE IF NOT EXISTS event_dedup (
    event_id TEXT PRIMARY KEY,
    fingerprint BIGINT NOT NULL,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS bridge_state (
    state_key TEXT PRIMARY KEY,
    state_value BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS webhook_replay_guard (
    replay_key TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS token_cache (
    cache_key TEXT PRIMARY KEY,
    token_value TEXT NOT NULL,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS outbound_dead_letters (
    event_id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    retriable BOOLEAN NOT NULL,
    last_error TEXT NOT NULL,
    event_json TEXT NOT NULL,
    first_seen_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL);
