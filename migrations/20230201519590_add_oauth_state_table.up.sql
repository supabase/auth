-- auth.oauth_state definition
create table if not exists {{ index .Options "Namespace" }}.oauth_state(
       id uuid primary key,
       internal_auth_code varchar(255) null,
       hashed_code_challenge varchar(255) unique null,
       provider_type varchar(255) null,
       redirect_uri text null,
       created_at timestamptz null,
       updated_at timestamptz null,
       unique(provider_type, hashed_code_challenge)
);
comment on table {{ index .Options "Namespace" }}.oauth_state is 'stores metadata for oauth provider logins';
