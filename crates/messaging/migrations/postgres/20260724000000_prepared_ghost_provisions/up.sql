CREATE TABLE prepared_ghost_provisions (
    id BIGSERIAL PRIMARY KEY,
    provision_key TEXT NOT NULL UNIQUE,
    request_json TEXT NOT NULL,
    created_at BIGINT NOT NULL);
