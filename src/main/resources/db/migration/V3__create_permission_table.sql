-- Create enum type for permission values
CREATE TYPE permission_value_enum AS ENUM (
    'VIEW_ALL_PAGES',
    'VIEW_DASHBOARD_PAGE',
    'VIEW_USERS_PAGE',
    'VIEW_RISK_OBJECTS_PAGE',
    'VIEW_INTEGRATIONS_PAGE',
    'VIEW_RULES_AND_RISKS_PAGE',
    'VIEW_SETTINGS_PAGE',
    'VIEW_PROFILE_PAGE',
    'EDIT_USERS',
    'MANAGE_RISK_OBJECTS',
    'MANAGE_INTEGRATIONS',
    'MANAGE_RULES_AND_RISKS'
);

-- Create permissions table linked to users
CREATE TABLE permissions (
                             id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                             user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                             value permission_value_enum[] NOT NULL DEFAULT '{}'::permission_value_enum[]
);

CREATE INDEX idx_permissions_user_id ON permissions(user_id);
