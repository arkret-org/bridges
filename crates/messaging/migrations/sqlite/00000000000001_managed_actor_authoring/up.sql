CREATE TABLE managed_actor_identities (
    subject_key TEXT PRIMARY KEY,
    actor_full_id TEXT NOT NULL UNIQUE,
    initial_resolution_json TEXT NOT NULL,
    method_history_evidence_json TEXT NOT NULL,
    encrypted_key_material TEXT NOT NULL,
    created_at BIGINT NOT NULL);

CREATE TABLE managed_actor_authorings (
    subject_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status TEXT NOT NULL,
    owner_token TEXT NOT NULL,
    lease_expires_at BIGINT NOT NULL,
    bundle_json TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (subject_key, request_digest),
    FOREIGN KEY (subject_key) REFERENCES managed_actor_identities(subject_key));
