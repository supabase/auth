-- Add SCIM provisioning support to SSO providers

do $$ begin
    alter table only {{ index .Options "Namespace" }}.sso_providers
        add column if not exists scim_enabled boolean null default false,
        add column if not exists scim_bearer_token_hash text null;
end $$;

comment on column {{ index .Options "Namespace" }}.sso_providers.scim_enabled is 'Auth: Whether SCIM provisioning is enabled for this SSO provider';
comment on column {{ index .Options "Namespace" }}.sso_providers.scim_bearer_token_hash is 'Auth: Bcrypt hash of the SCIM bearer token used by the IdP';
