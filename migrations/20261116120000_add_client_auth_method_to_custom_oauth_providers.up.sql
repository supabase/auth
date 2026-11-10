-- Let custom OAuth providers authenticate to the token endpoint with either a
-- client secret or a signed client assertion (private_key_jwt, RFC 7523).
-- Existing rows default to client_secret and keep their secret.
--
-- client_secret stays NOT NULL: private_key_jwt providers store an empty
-- string instead, so versions that predate this migration can still read every
-- row during a rolling deploy or after a rollback.
/* auth_migration: 20261116120000 */
do $$ begin

    alter table only {{ index .Options "Namespace" }}.custom_oauth_providers
        add column if not exists client_auth_method text not null default 'client_secret',
        -- Optional override for the assertion aud claim, which defaults to the
        -- provider's issuer.
        add column if not exists client_assertion_audience text null;

    if not exists (
        select 1 from pg_constraint
        where conname = 'custom_oauth_providers_client_auth_method_check'
          and conrelid = '{{ index .Options "Namespace" }}.custom_oauth_providers'::regclass
    ) then
        alter table only {{ index .Options "Namespace" }}.custom_oauth_providers
            add constraint custom_oauth_providers_client_auth_method_check check (
                client_auth_method in ('client_secret', 'private_key_jwt')
            );
    end if;

    -- client_secret providers must have a secret, private_key_jwt providers
    -- must not (an empty string).
    if not exists (
        select 1 from pg_constraint
        where conname = 'custom_oauth_providers_client_secret_matches_auth_method'
          and conrelid = '{{ index .Options "Namespace" }}.custom_oauth_providers'::regclass
    ) then
        alter table only {{ index .Options "Namespace" }}.custom_oauth_providers
            add constraint custom_oauth_providers_client_secret_matches_auth_method check (
                (client_auth_method = 'client_secret' and client_secret <> '') or
                (client_auth_method = 'private_key_jwt' and client_secret = '')
            );
    end if;

    if not exists (
        select 1 from pg_constraint
        where conname = 'custom_oauth_providers_client_assertion_audience_length'
          and conrelid = '{{ index .Options "Namespace" }}.custom_oauth_providers'::regclass
    ) then
        alter table only {{ index .Options "Namespace" }}.custom_oauth_providers
            add constraint custom_oauth_providers_client_assertion_audience_length check (
                client_assertion_audience is null or
                (char_length(client_assertion_audience) >= 1 and char_length(client_assertion_audience) <= 2048)
            );
    end if;

end $$;
