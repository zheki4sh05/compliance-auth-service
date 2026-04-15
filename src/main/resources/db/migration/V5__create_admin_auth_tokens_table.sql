-- Separate token storage for admin panel logins
CREATE TABLE admin_auth_tokens (
                                   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                   user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                   client_id VARCHAR(100) NOT NULL,
                                   access_token TEXT NOT NULL,
                                   refresh_token TEXT NOT NULL,
                                   access_token_expires_at TIMESTAMP,
                                   refresh_token_expires_at TIMESTAMP,
                                   created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_admin_auth_tokens_user_id ON admin_auth_tokens(user_id);
