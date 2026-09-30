/* auth_migration: 20260930000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_settings (
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    enabled boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint scim_settings_pkey primary key (sso_provider_id)
);
