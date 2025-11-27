/* auth_migration: 20251201000000 */
CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.oauth_states(
  id UUID PRIMARY KEY,
  provider_type TEXT NOT NULL,
  code_verifier TEXT,
  created_at TIMESTAMPTZ NOT NULL
);
/* auth_migration: 20251201000000 */
CREATE INDEX IF NOT EXISTS idx_oauth_states_created_at ON {{ index .Options "Namespace" }}.oauth_states(created_at);
/* auth_migration: 20251201000000 */
COMMENT ON TABLE {{ index .Options "Namespace" }}.oauth_states IS 'Stores OAuth states for third-party provider authentication flows.';
