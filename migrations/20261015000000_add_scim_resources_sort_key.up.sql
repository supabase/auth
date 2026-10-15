/* auth_migration: 20261015000000 */
alter table {{ index .Options "Namespace" }}.scim_resources
    add column if not exists sort_key text collate "C" generated always as (lower(coalesce(resource->>'userName', resource->>'displayName'))) stored;

create index if not exists scim_resources_sort_key_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, sort_key) include (id)
    where deleted_at is null;
