CREATE SCHEMA IF NOT EXISTS quarkus_auth;

CREATE TABLE IF NOT EXISTS quarkus_auth.resource_authorization
(
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    secured_endpoint_id  VARCHAR(255) NOT NULL,
    rule                 VARCHAR(255) NOT NULL,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_resource_authorization (secured_endpoint_id, rule)
) ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS quarkus_auth.endpoint_resolver
(
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    secured_endpoint_id  VARCHAR(255) NOT NULL,
    resource             VARCHAR(255) NOT NULL,
    original_field       VARCHAR(255) NOT NULL,
    mapped_field         VARCHAR(255) NOT NULL,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_endpoint_resolver (secured_endpoint_id, resource, original_field)
) ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS quarkus_auth.role_endpoint
(
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    role_name            VARCHAR(255) NOT NULL,
    role_id              VARCHAR(255) NOT NULL,
    secured_endpoint_id  VARCHAR(255) NOT NULL,
    scope                VARCHAR(50) NULL,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_role_endpoint (secured_endpoint_id, role_id)
) ROW_FORMAT=DYNAMIC;