-- SCIM Users provisioned into one SSO provider by an identity provider.
--
-- The SCIM resource is stored as a document because the attributes a provider
-- sends are its own configuration, not something this schema can enumerate. The
-- columns a query filters or orders by are generated from that document, so the
-- two cannot drift apart.
/* auth_migration: 20260821000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_users (
    id uuid not null default gen_random_uuid(),
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource jsonb not null,
    user_name text not null generated always as (resource->>'userName') stored,
    external_id text generated always as (resource->>'externalId') stored,
    active boolean not null generated always as (coalesce((resource->>'active')::boolean, true)) stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint scim_users_pkey primary key (id)
);

-- userName is unique within a provider and is not caseExact, so uniqueness
-- folds case. Soft-deleted rows are excluded, which lets a userName be reused
-- after the resource holding it is deleted.
/* auth_migration: 20260821000000 */
create unique index if not exists scim_users_user_name_key
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, lower(user_name))
    where deleted_at is null;

/* auth_migration: 20260821000000 */
create index if not exists scim_users_external_id_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, external_id)
    where deleted_at is null;

-- The sort indexes carry id as the last column because a SCIM window is only
-- correct over a total order, so every sort breaks its ties on id.
/* auth_migration: 20260821000000 */
create index if not exists scim_users_id_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, id)
    where deleted_at is null;

/* auth_migration: 20260821000000 */
create index if not exists scim_users_user_name_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, lower(user_name), id)
    where deleted_at is null;

/* auth_migration: 20260821000000 */
create index if not exists scim_users_created_at_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, created_at, id)
    where deleted_at is null;

/* auth_migration: 20260821000000 */
create index if not exists scim_users_updated_at_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, updated_at, id)
    where deleted_at is null;
