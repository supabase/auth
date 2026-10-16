/* auth_migration: 20261005000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_resources (
    id uuid not null,
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource_type text not null,
    resource jsonb not null,
    search jsonb not null generated always as (lower(resource::text)::jsonb) stored,
    sort_key text collate "C" generated always as (lower(coalesce(resource->>'userName', resource->>'displayName'))) stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint scim_resources_pkey primary key (id),
    constraint scim_resources_sso_provider_id_id_key unique (sso_provider_id, id)
);

/* auth_migration: 20261005000000 */
create unique index if not exists scim_resources_user_name_key
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, (lower(resource->>'userName')) collate "C")
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_type_id_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_sort_key_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, sort_key, id)
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
    target_type text not null,
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

/* auth_migration: 20261005000000 */
create or replace function {{ index .Options "Namespace" }}.scim_resources_delete_references()
returns trigger
language plpgsql
as $$
begin
  delete from {{ index .Options "Namespace" }}.scim_resource_references
  where source_id = new.id or target_id = new.id;
  return null;
end;
$$;

/* auth_migration: 20261005000000 */
create or replace trigger scim_resources_soft_delete
    after update of deleted_at on {{ index .Options "Namespace" }}.scim_resources
    for each row
    when (old.deleted_at is null and new.deleted_at is not null)
    execute function {{ index .Options "Namespace" }}.scim_resources_delete_references();
