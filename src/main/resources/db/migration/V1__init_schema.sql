-- Roles table
CREATE TABLE roles (
                       id BIGSERIAL PRIMARY KEY,
                       name VARCHAR(50) NOT NULL UNIQUE,
                       description VARCHAR(500)
);

-- Users table
CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       username VARCHAR(100) NOT NULL UNIQUE,
                       password VARCHAR(255) NOT NULL,
                       email VARCHAR(100) NOT NULL UNIQUE,
                       enabled BOOLEAN NOT NULL DEFAULT true,
                       account_non_expired BOOLEAN NOT NULL DEFAULT true,
                       account_non_locked BOOLEAN NOT NULL DEFAULT true,
                       credentials_non_expired BOOLEAN NOT NULL DEFAULT true,
                       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User-Roles junction table
CREATE TABLE user_roles (
                            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                            PRIMARY KEY (user_id, role_id)
);

-- OAuth2 Registered Clients
CREATE TABLE oauth2_registered_client (
                                          id VARCHAR(100) NOT NULL,
                                          client_id VARCHAR(100) NOT NULL,
                                          client_id_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                          client_secret VARCHAR(200),
                                          client_secret_expires_at TIMESTAMP,
                                          client_name VARCHAR(200) NOT NULL,
                                          client_authentication_methods VARCHAR(1000) NOT NULL,
                                          authorization_grant_types VARCHAR(1000) NOT NULL,
                                          redirect_uris VARCHAR(1000),
                                          scopes VARCHAR(1000) NOT NULL,
                                          client_settings VARCHAR(2000) NOT NULL,
                                          token_settings VARCHAR(2000) NOT NULL,
                                          post_logout_redirect_uris TEXT,
                                          PRIMARY KEY (id)
);

-- OAuth2 Authorizations (для хранения токенов)
CREATE TABLE oauth2_authorization (
                                      id VARCHAR(100) NOT NULL,
                                      registered_client_id VARCHAR(100) NOT NULL,
                                      principal_name VARCHAR(200) NOT NULL,
                                      authorization_grant_type VARCHAR(100) NOT NULL,
                                      authorized_scopes VARCHAR(1000),
                                      attributes TEXT,
                                      state VARCHAR(500),
                                      authorization_code_value TEXT,
                                      authorization_code_issued_at TIMESTAMP,
                                      authorization_code_expires_at TIMESTAMP,
                                      authorization_code_metadata TEXT,
                                      access_token_value TEXT,
                                      access_token_issued_at TIMESTAMP,
                                      access_token_expires_at TIMESTAMP,
                                      access_token_metadata TEXT,
                                      access_token_type VARCHAR(100),
                                      access_token_scopes VARCHAR(1000),
                                      refresh_token_value TEXT,
                                      refresh_token_issued_at TIMESTAMP,
                                      refresh_token_expires_at TIMESTAMP,
                                      refresh_token_metadata TEXT,
                                      oidc_id_token_value TEXT,
                                      oidc_id_token_issued_at TIMESTAMP,
                                      oidc_id_token_expires_at TIMESTAMP,
                                      oidc_id_token_metadata TEXT,
                                      oidc_id_token_claims TEXT,
                                      user_code_value TEXT,
                                      user_code_issued_at TIMESTAMP,
                                      user_code_expires_at TIMESTAMP,
                                      user_code_metadata TEXT,
                                      device_code_value TEXT,
                                      device_code_issued_at TIMESTAMP,
                                      device_code_expires_at TIMESTAMP,
                                      device_code_metadata TEXT,
                                      PRIMARY KEY (id)
);

-- OAuth2 Authorization Consent
CREATE TABLE oauth2_authorization_consent (
                                              registered_client_id VARCHAR(100) NOT NULL,
                                              principal_name VARCHAR(200) NOT NULL,
                                              authorities VARCHAR(1000) NOT NULL,
                                              PRIMARY KEY (registered_client_id, principal_name)
);

-- Indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_oauth2_authorization_principal ON oauth2_authorization(principal_name);
CREATE INDEX idx_oauth2_authorization_client ON oauth2_authorization(registered_client_id);

-- Insert default roles
INSERT INTO roles (name, description) VALUES
                                          ('MANAGER', 'Manager role with basic permissions'),
                                          ('SUPERVISOR', 'Supervisor role with elevated permissions'),
                                          ('EXECUTIVE', 'Executive role with full administrative permissions'),
                                          ('DEFAULT', 'Default role for newly registered users');

-- Insert default users (passwords: manager123, supervisor123, executive123)
INSERT INTO users (username, password, email) VALUES
                                                  ('manager', '{bcrypt}$2a$12$LQv3c1yqBWVHxkltdWFQg.WJw1oXNAYYzGqnXxzzfQZgI4g6KdOYi', 'manager@company.com'),
                                                  ('supervisor', '{bcrypt}$2a$12$XPxRCPhZsZzL5HdI.aZHn.Xb.7VDqfPBb7KpYZ0CqGCk4wXPdxjiu', 'supervisor@company.com'),
                                                  ('executive', '{bcrypt}$2a$12$7ZG7fGGQf8wYq0YgKKVLQ.hO5d7HrCqWLxJZ0jQUzKXqzX7N7xY7e', 'executive@company.com');

-- Assign roles to users
INSERT INTO user_roles (user_id, role_id) VALUES
                                              (1, 1), -- manager -> MANAGER
                                              (2, 2), -- supervisor -> SUPERVISOR
                                              (3, 3); -- executive -> EXECUTIVE
