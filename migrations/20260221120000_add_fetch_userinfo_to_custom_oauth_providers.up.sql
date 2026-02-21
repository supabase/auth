-- Add fetch_userinfo column to custom_oauth_providers
-- When true for OIDC providers, UserInfo endpoint is called after ID token
-- verification and claims are merged. Useful for providers like NHS CIS2
-- where profile/role data is only available via UserInfo, not the ID token.

/* auth_migration: 20260221120000 */
ALTER TABLE {{ index .Options "Namespace" }}.custom_oauth_providers
    ADD COLUMN IF NOT EXISTS fetch_userinfo boolean NOT NULL DEFAULT false;
