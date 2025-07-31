-- Create oauth_clients table for OAuth client management
create table if not exists {{ index .Options "Namespace" }}.oauth_clients (
    id uuid not null,
    client_id varchar(255) not null,
    client_secret_hash text not null,
    registration_type varchar(20) not null check (registration_type in ('dynamic', 'manual')),
    redirect_uris text not null,
    grant_types text not null default 'authorization_code,refresh_token' check (grant_types ~ '^(authorization_code|refresh_token)(,(authorization_code|refresh_token))*$'),
    client_name varchar(255) null,
    client_uri text null,
    logo_uri text null,
    created_at timestamptz default now(),
    updated_at timestamptz default now(),
    deleted_at timestamptz null,
    constraint oauth_clients_pkey primary key (id),
    constraint oauth_clients_client_id_key unique (client_id)
);

comment on table {{ index .Options "Namespace" }}.oauth_clients is 'Auth: Stores OAuth client application registrations for OAuth 2.1 flows.';
comment on column {{ index .Options "Namespace" }}.oauth_clients.client_id is 'Public identifier for the OAuth client';
comment on column {{ index .Options "Namespace" }}.oauth_clients.client_secret_hash is 'Bcrypt hash of client secret';
comment on column {{ index .Options "Namespace" }}.oauth_clients.registration_type is 'Client registration type: dynamic or manual';
comment on column {{ index .Options "Namespace" }}.oauth_clients.redirect_uris is 'Comma-separated list of allowed redirect URIs';
comment on column {{ index .Options "Namespace" }}.oauth_clients.grant_types is 'Comma-separated list of allowed grant types';
comment on column {{ index .Options "Namespace" }}.oauth_clients.client_name is 'Human-readable client name for authorization UI';
comment on column {{ index .Options "Namespace" }}.oauth_clients.client_uri is 'URL of client information page';
comment on column {{ index .Options "Namespace" }}.oauth_clients.logo_uri is 'URL of client logo for authorization UI';

-- Create indexes
create index if not exists oauth_clients_client_id_idx 
    on {{ index .Options "Namespace" }}.oauth_clients (client_id);

create index if not exists oauth_clients_deleted_at_idx 
    on {{ index .Options "Namespace" }}.oauth_clients (deleted_at);
