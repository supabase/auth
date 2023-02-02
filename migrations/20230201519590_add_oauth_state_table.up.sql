-- auth.oauth_state definition
create table if not exists {{ index .Options "Namespace" }}.oauth_state(
       id uuid not null,
       internal_auth_code varchar(255) unique null,
       hashed_code_challenge varchar(255) null,
       provider_type varchar(255) null,
       created_at timestamptz null,
       updated_at timestamptz null,
       constraint oauth_state_pkey primary key(id),
       unique(internal_auth_code, hashed_code_challenge)
);
comment on table {{ index .Options "Namespace" }}.oauth_state is 'stores metadata for oauth provider logins';
