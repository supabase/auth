-- Persist per-provider OAuth canonical-email sync across the authorize/callback
-- round-trip (flow_state) and on admin-managed custom OAuth/OIDC providers.
/* auth_migration: 20260818120000 */
ALTER TABLE {{ index .Options "Namespace" }}.flow_state
    ADD COLUMN IF NOT EXISTS sync_email BOOLEAN NOT NULL DEFAULT FALSE;

/* auth_migration: 20260818120000 */
ALTER TABLE {{ index .Options "Namespace" }}.custom_oauth_providers
    ADD COLUMN IF NOT EXISTS sync_email BOOLEAN NOT NULL DEFAULT FALSE;
