CREATE TABLE IF NOT EXISTS transaction_idempotency (
    source_service_did VARCHAR(191) NOT NULL,
    idempotency_key VARCHAR(191) NOT NULL,
    body_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (source_service_did, idempotency_key));

CREATE TABLE IF NOT EXISTS event_dedup (
    event_id VARCHAR(191) PRIMARY KEY,
    fingerprint BIGINT NOT NULL,
    expires_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS bridge_state (
    state_key VARCHAR(191) PRIMARY KEY,
    state_value BIGINT NOT NULL);
