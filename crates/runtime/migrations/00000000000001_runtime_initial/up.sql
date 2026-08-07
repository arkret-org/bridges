CREATE TABLE IF NOT EXISTS transaction_idempotency (
    operation_id VARCHAR(96) NOT NULL,
    direction VARCHAR(32) NOT NULL,
    source_service_id VARCHAR(191) NOT NULL,
    destination_service_id VARCHAR(191) NOT NULL,
    idempotency_key VARCHAR(191) NOT NULL,
    body_hash TEXT NOT NULL,
    source_signature_anchor TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome TEXT,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (
        operation_id,
        direction,
        source_service_id,
        destination_service_id,
        idempotency_key
    ));

CREATE TABLE IF NOT EXISTS event_dedup (
    event_id VARCHAR(191) PRIMARY KEY,
    fingerprint BIGINT NOT NULL,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS bridge_state (
    state_key VARCHAR(191) PRIMARY KEY,
    state_value BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS webhook_replay_guard (
    replay_key VARCHAR(191) PRIMARY KEY,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS token_cache (
    cache_key VARCHAR(191) PRIMARY KEY,
    token_value TEXT NOT NULL,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS outbound_dead_letters (
    event_id VARCHAR(191) PRIMARY KEY,
    realm_id VARCHAR(191) NOT NULL,
    kind VARCHAR(191) NOT NULL,
    attempts INTEGER NOT NULL,
    retriable BOOLEAN NOT NULL,
    last_error TEXT NOT NULL,
    event_json TEXT NOT NULL,
    first_seen_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL);
