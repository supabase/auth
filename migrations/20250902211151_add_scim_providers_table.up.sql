-- Create scim_providers table for SCIM provider authentication
create table if not exists {{ index .Options "Namespace" }}.scim_providers (
    id uuid not null,
    name text not null,
    password_hash text not null,
    audience text null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz null,
    constraint scim_providers_pkey primary key (id),
    constraint scim_providers_name_key unique (name),
    constraint scim_providers_name_length check (char_length(name) <= 255)
);

-- Create indexes
create index if not exists scim_providers_name_idx 
    on {{ index .Options "Namespace" }}.scim_providers (name);

create index if not exists scim_providers_deleted_at_idx 
    on {{ index .Options "Namespace" }}.scim_providers (deleted_at);

create index if not exists scim_providers_audience_idx 
    on {{ index .Options "Namespace" }}.scim_providers (audience);