CREATE TABLE IF NOT EXISTS room_mappings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    app_channel_id TEXT NOT NULL,
    cokret_realm_id TEXT NOT NULL,
    portal_alias TEXT,
    portal_strand_id TEXT,
    created_at BIGINT NOT NULL,
    UNIQUE KEY room_app_channel_id_unique (app_channel_id(191)),
    UNIQUE KEY room_cokret_realm_id_unique (cokret_realm_id(191)));

CREATE TABLE IF NOT EXISTS message_mappings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    app_channel_id TEXT NOT NULL,
    app_message_id TEXT NOT NULL,
    normalized_sender TEXT NOT NULL,
    cokret_event_id TEXT NOT NULL,
    cokret_realm_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE KEY message_app_id_unique
        (app_channel_id(191), app_message_id(120), normalized_sender(120)),
    UNIQUE KEY message_cokret_event_id_unique (cokret_event_id(191)));

CREATE TABLE IF NOT EXISTS user_mappings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    protocol TEXT NOT NULL,
    tenant TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    cokret_actor_id TEXT NOT NULL,
    profile_event_ref TEXT NOT NULL,
    accountability_grant_ref TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    display_name TEXT,
    created_at BIGINT NOT NULL,
    UNIQUE KEY user_protocol_tenant_external_id_unique
        (protocol(64), tenant(191), external_user_id(191)),
    UNIQUE KEY user_cokret_actor_id_unique (cokret_actor_id(191)));
