-- Add SCIM provisioning support

-- Add SCIM columns to SSO providers
do $$ begin
    alter table only {{ index .Options "Namespace" }}.sso_providers
        add column if not exists scim_enabled boolean null default false,
        add column if not exists scim_bearer_token_hash text null;
end $$;

comment on column {{ index .Options "Namespace" }}.sso_providers.scim_enabled is 'Auth: Whether SCIM provisioning is enabled for this SSO provider';
comment on column {{ index .Options "Namespace" }}.sso_providers.scim_bearer_token_hash is 'Auth: SHA-256 hash of the SCIM bearer token used by the IdP';

-- Index for direct SCIM token hash lookup
create unique index if not exists sso_providers_scim_token_hash_idx
    on {{ index .Options "Namespace" }}.sso_providers (scim_bearer_token_hash)
    where scim_bearer_token_hash is not null;

-- Add banned_reason to users for SCIM deprovisioning
do $$ begin
    alter table only {{ index .Options "Namespace" }}.users
        add column if not exists banned_reason text null;
end $$;

comment on column {{ index .Options "Namespace" }}.users.banned_reason is 'Auth: Reason for user ban (e.g., SCIM_DEPROVISIONED)';

-- SCIM Groups
create table if not exists {{ index .Options "Namespace" }}.scim_groups (
    id uuid not null,
    sso_provider_id uuid not null,
    external_id text null,
    display_name text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),

    constraint scim_groups_pkey primary key (id),
    constraint scim_groups_sso_provider_fkey foreign key (sso_provider_id)
        references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    constraint "external_id not empty if set" check (external_id is null or char_length(external_id) > 0),
    constraint "display_name not empty" check (char_length(display_name) > 0)
);

create unique index if not exists scim_groups_sso_provider_external_id_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, external_id)
    where external_id is not null;

create unique index if not exists scim_groups_sso_provider_display_name_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, lower(display_name));

create index if not exists scim_groups_sso_provider_id_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id);

comment on table {{ index .Options "Namespace" }}.scim_groups is 'Auth: Manages SCIM groups provisioned by SSO identity providers.';
comment on column {{ index .Options "Namespace" }}.scim_groups.external_id is 'Auth: The group ID from the external identity provider.';
comment on column {{ index .Options "Namespace" }}.scim_groups.display_name is 'Auth: Human-readable name of the group.';

-- SCIM Group Members
create table if not exists {{ index .Options "Namespace" }}.scim_group_members (
    group_id uuid not null,
    user_id uuid not null,
    created_at timestamptz not null default now(),

    constraint scim_group_members_pkey primary key (group_id, user_id),
    constraint scim_group_members_group_fkey foreign key (group_id)
        references {{ index .Options "Namespace" }}.scim_groups (id) on delete cascade,
    constraint scim_group_members_user_fkey foreign key (user_id)
        references {{ index .Options "Namespace" }}.users (id) on delete cascade
);

create index if not exists scim_group_members_user_id_idx
    on {{ index .Options "Namespace" }}.scim_group_members (user_id);

comment on table {{ index .Options "Namespace" }}.scim_group_members is 'Auth: Junction table for SCIM group membership.';
