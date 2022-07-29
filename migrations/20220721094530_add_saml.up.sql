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

comment on table auth.saml_providers is 'Auth: Manages SAML Identity Provider connections.';
