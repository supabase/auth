-- SCIM Groups; RFC 7643 Group
create table if not exists {{ index .Options "Namespace" }}.scim_groups (
    id uuid not null default gen_random_uuid(),
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource jsonb not null,
    display_name text not null generated always as (resource->>'displayName') stored,
    external_id text generated always as (resource->>'externalId') stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint scim_groups_pkey primary key (id)
);

-- displayName is unique within a provider, case-folded.
create unique index if not exists scim_groups_display_name_key
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, lower(display_name));

-- Group membership. The composite key prevents duplicate (group, user) rows.
create table if not exists {{ index .Options "Namespace" }}.scim_group_members (
    scim_group_id uuid not null references {{ index .Options "Namespace" }}.scim_groups (id) on delete cascade,
    scim_user_id uuid not null references {{ index .Options "Namespace" }}.scim_users (id) on delete cascade,
    constraint scim_group_members_pkey primary key (scim_group_id, scim_user_id)
);
