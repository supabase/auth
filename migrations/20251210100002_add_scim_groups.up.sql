-- Add SCIM Groups support for SSO identity providers

create table if not exists {{ index .Options "Namespace" }}.scim_groups (
    id uuid not null,
    sso_provider_id uuid not null,
    external_id text null,
    display_name text not null,
    created_at timestamptz null,
    updated_at timestamptz null,

    constraint scim_groups_pkey primary key (id),
    constraint scim_groups_sso_provider_fkey foreign key (sso_provider_id)
        references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    constraint "external_id not empty if set" check (external_id is null or char_length(external_id) > 0),
    constraint "display_name not empty" check (char_length(display_name) > 0)
);

-- Unique index scoped to SSO provider (only for non-null external_id)
create unique index if not exists scim_groups_sso_provider_external_id_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, external_id)
    where external_id is not null;

-- Unique index for displayName per SSO provider (case-insensitive, required by Azure AD)
create unique index if not exists scim_groups_sso_provider_display_name_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, lower(display_name));

-- Index for listing groups by SSO provider
create index if not exists scim_groups_sso_provider_id_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id);

comment on table {{ index .Options "Namespace" }}.scim_groups is 'Auth: Manages SCIM groups provisioned by SSO identity providers.';
comment on column {{ index .Options "Namespace" }}.scim_groups.external_id is 'Auth: The group ID from the external identity provider.';
comment on column {{ index .Options "Namespace" }}.scim_groups.display_name is 'Auth: Human-readable name of the group.';

create table if not exists {{ index .Options "Namespace" }}.scim_group_members (
    group_id uuid not null,
    user_id uuid not null,
    created_at timestamptz null,

    constraint scim_group_members_pkey primary key (group_id, user_id),
    constraint scim_group_members_group_fkey foreign key (group_id)
        references {{ index .Options "Namespace" }}.scim_groups (id) on delete cascade,
    constraint scim_group_members_user_fkey foreign key (user_id)
        references {{ index .Options "Namespace" }}.users (id) on delete cascade
);

-- Index for groups that the user belong to
create index if not exists scim_group_members_user_id_idx
    on {{ index .Options "Namespace" }}.scim_group_members (user_id);

comment on table {{ index .Options "Namespace" }}.scim_group_members is 'Auth: Junction table for SCIM group membership.';
