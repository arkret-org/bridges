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
    profile_event_ref TEXT NOT NULL,
    accountability_grant_ref TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    display_name TEXT,
    created_at BIGINT NOT NULL,
    UNIQUE(protocol, tenant, external_user_id));
