-- Add user profile fields
ALTER TABLE users
    ADD COLUMN first_name VARCHAR(100),
    ADD COLUMN last_name VARCHAR(100),
    ADD COLUMN is_first_login BOOLEAN NOT NULL DEFAULT true;