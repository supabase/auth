-- Let custom OAuth providers authenticate to the token endpoint with either a
-- client secret or a signed client assertion (private_key_jwt, RFC 7523).
-- Existing rows default to client_secret and keep their secret.
--
-- client_secret stays NOT NULL: private_key_jwt providers store an empty
-- string instead, so versions that predate this migration can still read every
-- row during a rolling deploy or after a rollback.
--
-- The allowed methods, which methods need a secret, and the audience length
-- are enforced by the admin API, not by check constraints.
/* auth_migration: 20261116120000 */
alter table only {{ index .Options "Namespace" }}.custom_oauth_providers
    add column if not exists client_auth_method text not null default 'client_secret',
    -- Optional override for the assertion aud claim, which defaults to the
    -- provider's issuer.
    add column if not exists client_assertion_audience text null;
