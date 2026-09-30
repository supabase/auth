/* auth_migration: 20260929000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_groups (
    id uuid not null,
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource jsonb not null,
    display_name text not null generated always as (lower(resource->>'displayName')) stored,
    external_id text generated always as (resource->>'externalId') stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint scim_groups_pkey primary key (id)
);

/* auth_migration: 20260929000000 */
create index if not exists scim_groups_display_name_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, display_name collate "C", id);

/* auth_migration: 20260929000000 */
create unique index if not exists scim_groups_external_id_key
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, external_id)
    where external_id is not null;

/* auth_migration: 20260929000000 */
create index if not exists scim_groups_created_at_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, created_at, id);

/* auth_migration: 20260929000000 */
create index if not exists scim_groups_updated_at_idx
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, updated_at, id);

/* auth_migration: 20260929000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_group_members (
    group_id uuid not null references {{ index .Options "Namespace" }}.scim_groups (id) on delete cascade,
    scim_user_id uuid not null references {{ index .Options "Namespace" }}.scim_users (id) on delete cascade,
    created_at timestamptz not null default now(),
    constraint scim_group_members_pkey primary key (group_id, scim_user_id)
);

/* auth_migration: 20260929000000 */
create index if not exists scim_group_members_scim_user_id_idx
    on {{ index .Options "Namespace" }}.scim_group_members (scim_user_id);
