do $$ 
begin
    create table if not exists {{ index .Options "Namespace" }}.oidc_providers (
        id uuid not null,
        sso_provider_id uuid not null,
        issuer text not null,
        client_id text not null,
        secret text not null,
        auth_url text not null,
        token_url text not null,
        userinfo_url text not null,
        redirect_uri text not null,
        -- metadata_url text null,
        attribute_mapping jsonb null,
        created_at timestamptz null,
        updated_at timestamptz null,
        primary key (id),
        foreign key (sso_provider_id) references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade
        -- constraint "metadata_xml not empty" check (char_length(metadata_xml) > 0),
        -- constraint "metadata_url not empty" check (metadata_url = null or char_length(metadata_url) > 0),
        -- constraint "entity_id not empty" check (char_length(entity_id) > 0)
    );

    create index if not exists oidc_providers_sso_provider_id_idx on {{ index .Options "Namespace" }}.oidc_providers (sso_provider_id);

    comment on table {{ index .Options "Namespace" }}.oidc_providers is 'Auth: Manages OIDC Identity Provider connections.';

    create table if not exists {{ index .Options "Namespace" }}.oidc_relay_states (
        id uuid not null,
        sso_provider_id uuid not null,
        state text not null,
        for_email text null,
        redirect_to text null,
        created_at timestamptz null,
        updated_at timestamptz null,
        flow_state_id uuid null,
        primary key (id),
        foreign key (sso_provider_id) references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
        foreign key (flow_state_id) references {{ index .Options "Namespace" }}.flow_state (id) on delete cascade,
        constraint "state not empty" check(char_length(state) > 0)
    );

    create index if not exists oidc_relay_states_sso_provider_id_idx on {{ index .Options "Namespace" }}.oidc_relay_states (sso_provider_id);
    create index if not exists oidc_relay_states_for_email_idx on {{ index .Options "Namespace" }}.oidc_relay_states (for_email);

    comment on table {{ index .Options "Namespace" }}.oidc_relay_states is 'Auth: Contains OIDC Relay State information for each Service Provider initiated login.';


end $$;
