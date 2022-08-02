-- Multi-instance mode (see auth.instances) table intentionally not supported and ignored.

create table if not exists auth.sso_providers (
	id uuid not null,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id)
);

comment on table auth.sso_providers is 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';

create table if not exists auth.sso_domains (
	id uuid not null,
	sso_provider_id uuid not null,
	domain text not null unique,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade,
	constraint "domain not empty" check (char_length(domain) > 0)
);

create index if not exists sso_domains_sso_provider_id_idx on auth.sso_domains (sso_provider_id);

comment on table auth.sso_domains is 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';

create table if not exists auth.saml_providers (
	id uuid not null,
	sso_provider_id uuid not null,
	entity_id text not null unique,
	metadata_xml text not null,
	metadata_url text null,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade,
	constraint "metadata_xml not empty" check (char_length(metadata_xml) > 0),
	constraint "entity_id not empty" check (char_length(entity_id) > 0)
);

create index if not exists saml_providers_sso_provider_id_idx on auth.saml_providers (sso_provider_id);

comment on table auth.saml_providers is 'Auth: Manages SAML Identity Provider connections.';

create table if not exists auth.sso_sessions (
	id uuid not null,
	user_id uuid not null,
	sso_provider_id uuid null,
	not_before timestamptz null,
	not_after timestamptz null,
	idp_initiated boolean default false,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	foreign key (user_id) references auth.users (id) on delete cascade,
	foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade
);

create index if not exists sso_sessions_sso_provider_id_idx on auth.sso_sessions (sso_provider_id);
create index if not exists sso_sessions_user_id_idx on auth.users (id);

comment on table auth.sso_sessions is 'Auth: A session initiated by an SSO Identity Provider';

alter table auth.refresh_tokens
	add column if not exists sso_session_id uuid null,
	drop constraint if exists refresh_tokens_session_id_fkey,
	add constraint refresh_tokens_session_id_fkey foreign key (sso_session_id) references auth.sso_sessions (id) on delete cascade;

create index if not exists refresh_tokens_sso_session_id_idx on auth.refresh_tokens (sso_session_id);

