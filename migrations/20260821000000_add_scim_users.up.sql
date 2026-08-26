-- SCIM Users provisioned into one SSO provider. The resource is stored as a
-- document; queryable columns are generated from it so the two cannot drift.
create table if not exists {{ index .Options "Namespace" }}.scim_users (
    id uuid not null default gen_random_uuid(),
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    user_id uuid references {{ index .Options "Namespace" }}.users (id) on delete set null,
    resource jsonb not null,
    user_name text not null generated always as (resource->>'userName') stored,
    external_id text generated always as (resource->>'externalId') stored,
    active boolean not null generated always as (coalesce((resource->>'active')::boolean, true)) stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint scim_users_pkey primary key (id),
    constraint scim_users_id_provider_key unique (id, sso_provider_id)
);

-- userName is unique within a provider, case-folded, excluding soft-deleted rows.
create unique index if not exists scim_users_user_name_key
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, lower(user_name) collate "C")
    where deleted_at is null;

-- externalId is unique within a provider when set; nulls are unconstrained.
create unique index if not exists scim_users_external_id_key
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, external_id)
    where external_id is not null and deleted_at is null;

-- Links a SCIM user to its auth.users row; null until first sign-in.
create index if not exists scim_users_user_id_idx
    on {{ index .Options "Namespace" }}.scim_users (user_id)
    where deleted_at is null;

-- Sort indexes break ties on id for a total order; user_name uses collate "C"
-- so ordering does not depend on the database's collation.
create index if not exists scim_users_id_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, id)
    where deleted_at is null;

create index if not exists scim_users_user_name_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, lower(user_name) collate "C", id)
    where deleted_at is null;

create index if not exists scim_users_created_at_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, created_at, id)
    where deleted_at is null;

create index if not exists scim_users_updated_at_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, updated_at, id)
    where deleted_at is null;

create index if not exists scim_users_sso_provider_id_idx
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id);

alter table {{ index .Options "Namespace" }}.scim_users enable row level security;
grant select on {{ index .Options "Namespace" }}.scim_users to postgres with grant option;
