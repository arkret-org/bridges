CREATE TABLE IF NOT EXISTS channel_realm_mappings (
    id BIGSERIAL PRIMARY KEY,
    app_channel_id TEXT NOT NULL UNIQUE,
    arkret_realm_id TEXT NOT NULL UNIQUE,
    portal_alias TEXT,
    portal_strand_id TEXT,
    created_at BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS message_mappings (
    id BIGSERIAL PRIMARY KEY,
    app_channel_id TEXT NOT NULL,
    app_message_id TEXT NOT NULL,
    normalized_sender TEXT NOT NULL,
    arkret_event_id TEXT NOT NULL UNIQUE,
    arkret_realm_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE(app_channel_id, app_message_id, normalized_sender));

CREATE TABLE IF NOT EXISTS user_mappings (
    id BIGSERIAL PRIMARY KEY,
    protocol TEXT NOT NULL,
    tenant TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    arkret_actor_id TEXT NOT NULL UNIQUE,
    arkret_actor_did TEXT NOT NULL,
    profile_event_ref TEXT NOT NULL,
    accountability_grant_ref TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    display_name TEXT,
    created_at BIGINT NOT NULL,
    UNIQUE(protocol, tenant, external_user_id));

CREATE TABLE IF NOT EXISTS prepared_ghost_provisions (
    id BIGSERIAL PRIMARY KEY,
    provision_key TEXT NOT NULL UNIQUE,
    request_json TEXT NOT NULL,
    created_at BIGINT NOT NULL);

CREATE TABLE managed_actor_identities (
    subject_key TEXT PRIMARY KEY,
    actor_did TEXT NOT NULL UNIQUE,
    initial_resolution_json TEXT NOT NULL,
    method_history_evidence_json TEXT NOT NULL,
    encrypted_key_material TEXT NOT NULL,
    created_at BIGINT NOT NULL);

CREATE TABLE managed_actor_authorings (
    subject_key TEXT NOT NULL REFERENCES managed_actor_identities(subject_key),
    request_digest TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status TEXT NOT NULL,
    owner_token TEXT NOT NULL,
    lease_expires_at BIGINT NOT NULL,
    bundle_json TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (subject_key, request_digest));
