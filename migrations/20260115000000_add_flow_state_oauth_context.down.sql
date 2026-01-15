-- Note: Cannot easily restore NOT NULL constraints without handling existing NULL values
-- This down migration removes the new columns but leaves the nullable constraints

-- Remove new columns
ALTER TABLE {{ index .Options "Namespace" }}.flow_state
    DROP COLUMN IF EXISTS invite_token,
    DROP COLUMN IF EXISTS referrer,
    DROP COLUMN IF EXISTS oauth_client_state_id,
    DROP COLUMN IF EXISTS linking_target_id,
    DROP COLUMN IF EXISTS email_optional;

COMMENT ON TABLE {{ index .Options "Namespace" }}.flow_state
    IS 'stores metadata for pkce logins';
