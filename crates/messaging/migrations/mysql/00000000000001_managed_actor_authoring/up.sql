CREATE TABLE managed_actor_identities (
    subject_key VARCHAR(191) PRIMARY KEY,
    actor_full_id VARCHAR(512) NOT NULL UNIQUE,
    initial_resolution_json LONGTEXT NOT NULL,
    method_history_evidence_json LONGTEXT NOT NULL,
    encrypted_key_material LONGTEXT NOT NULL,
    created_at BIGINT NOT NULL);

CREATE TABLE managed_actor_authorings (
    subject_key VARCHAR(191) NOT NULL,
    request_digest VARCHAR(191) NOT NULL,
    request_json LONGTEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    owner_token VARCHAR(191) NOT NULL,
    lease_expires_at BIGINT NOT NULL,
    bundle_json LONGTEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (subject_key, request_digest),
    CONSTRAINT managed_actor_authoring_identity_fk
        FOREIGN KEY (subject_key) REFERENCES managed_actor_identities(subject_key));
