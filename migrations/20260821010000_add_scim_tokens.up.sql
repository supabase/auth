-- Bearer tokens authorising SCIM requests on behalf of one SSO provider.
--
-- Only the SHA-256 digest of a token is stored.
-- A token carries 160 bits of randomness, so the digest needs no salt
create table if not exists {{ index .Options "Namespace" }}.scim_tokens (
    id uuid not null default gen_random_uuid(),
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    token_hash text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    constraint scim_tokens_pkey primary key (id),
    constraint scim_tokens_token_hash_check check (token_hash ~ '^[0-9a-f]{64}$')
);

-- The digest is how a request is resolved to a provider, so it is unique across
-- every provider and not merely within one.
create unique index if not exists scim_tokens_token_hash_key
    on {{ index .Options "Namespace" }}.scim_tokens (token_hash);

-- Deliberately not unique: rotating a token means two of them are live for one
-- provider until the old one is revoked.
create index if not exists scim_tokens_sso_provider_id_idx
    on {{ index .Options "Namespace" }}.scim_tokens (sso_provider_id)
    where revoked_at is null;
