-- Add super user flag to users
ALTER TABLE users
    ADD COLUMN is_super_user BOOLEAN NOT NULL DEFAULT false;
