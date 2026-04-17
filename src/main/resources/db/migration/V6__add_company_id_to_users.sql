ALTER TABLE users
    ADD COLUMN company_id UUID;

CREATE INDEX idx_users_company_id ON users(company_id);
