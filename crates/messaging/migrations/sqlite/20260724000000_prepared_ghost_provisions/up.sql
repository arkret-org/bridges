CREATE TABLE prepared_ghost_provisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provision_key TEXT NOT NULL UNIQUE,
    request_json TEXT NOT NULL,
    created_at BIGINT NOT NULL);
