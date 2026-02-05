-- Add SCIM provisioning support to SSO providers

do $$ begin
    alter table only {{ index .Options "Namespace" }}.sso_providers
        add column if not exists scim_enabled boolean null default false,
        add column if not exists scim_bearer_token_hash text null;
end $$;

comment on column {{ index .Options "Namespace" }}.sso_providers.scim_enabled is 'Auth: Whether SCIM provisioning is enabled for this SSO provider';
comment on column {{ index .Options "Namespace" }}.sso_providers.scim_bearer_token_hash is 'Auth: Hash of the SCIM bearer token used by the IdP';

-- Partial index for SCIM token lookup (only SCIM-enabled providers with a token)
create index if not exists sso_providers_scim_enabled_idx
    on {{ index .Options "Namespace" }}.sso_providers (id)
    where scim_enabled = true and scim_bearer_token_hash is not null;
