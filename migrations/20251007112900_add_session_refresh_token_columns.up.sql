ALTER TABLE {{ index .Options "Namespace" }}.sessions
  ADD COLUMN IF NOT EXISTS refresh_token_hmac_key text,
  ADD COLUMN IF NOT EXISTS refresh_token_counter bigint;

COMMENT ON COLUMN {{ index .Options "Namespace" }}.sessions.refresh_token_hmac_key IS 'Holds a HMAC-SHA256 key used to sign refresh tokens for this session.';
COMMENT ON COLUMN {{ index .Options "Namespace" }}.sessions.refresh_token_counter IS 'Holds the ID (counter) of the last issued refresh token.';
