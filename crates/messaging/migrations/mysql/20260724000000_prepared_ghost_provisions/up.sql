CREATE TABLE prepared_ghost_provisions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    provision_key VARCHAR(191) NOT NULL UNIQUE,
    request_json LONGTEXT NOT NULL,
    created_at BIGINT NOT NULL);
