-- Holds the SHA-256 hex digest of the provider's SCIM token.
/* auth_migration: 20260731000000 */
alter table only {{ index .Options "Namespace" }}.sso_providers
    add column if not exists scim_token_hash text null;

/* auth_migration: 20260731000000 */
create unique index if not exists sso_providers_scim_token_hash_idx
    on {{ index .Options "Namespace" }}.sso_providers (scim_token_hash)
        where scim_token_hash is not null;
