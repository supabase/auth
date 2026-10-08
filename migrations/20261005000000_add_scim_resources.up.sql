/* auth_migration: 20261005000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_resources (
    id uuid not null,
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource_type text not null,
    resource jsonb not null,
    search jsonb not null generated always as (lower(resource::text)::jsonb) stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint scim_resources_pkey primary key (id),
    constraint scim_resources_sso_provider_id_id_key unique (sso_provider_id, id)
);

/* auth_migration: 20261005000000 */
create unique index if not exists scim_resources_user_name_key
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, (lower(resource->>'userName')) collate "C")
    where resource_type = 'User' and deleted_at is null;

/* auth_migration: 20261005000000 */
create unique index if not exists scim_resources_external_id_key
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, (resource->>'externalId') collate "C")
    where resource->>'externalId' is not null and deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_display_name_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, (lower(resource->>'displayName')) collate "C", id)
    where resource_type = 'Group' and deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_type_id_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_updated_at_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, updated_at, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_type_idx
    on {{ index .Options "Namespace" }}.scim_resources (id) include (resource_type)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_resource_idx
    on {{ index .Options "Namespace" }}.scim_resources using gin (search jsonb_path_ops)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_resource_references (
    sso_provider_id uuid not null,
    source_id uuid not null,
    attribute text not null,
    target_id uuid not null,
    constraint scim_resource_references_pkey primary key (source_id, attribute, target_id),
    constraint scim_resource_references_not_self check (source_id <> target_id),
    constraint scim_resource_references_source_fkey foreign key (sso_provider_id, source_id)
        references {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, id) on delete cascade,
    constraint scim_resource_references_target_fkey foreign key (sso_provider_id, target_id)
        references {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, id) on delete cascade
);

/* auth_migration: 20261005000000 */
create index if not exists scim_resource_references_target_idx
    on {{ index .Options "Namespace" }}.scim_resource_references (target_id, attribute);
