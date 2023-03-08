-- auth.oauth_state definition
create table if not exists {{ index .Options "Namespace" }}.oauth_state(
       id uuid primary key,
       user_id uuid null,
       auth_code text unique not null,
       code_challenge text not null,
       provider_type text null,
       provider_access_token text null,
       provider_refresh_token text null,
       created_at timestamptz null,
       updated_at timestamptz null
);
create index idx_auth_code on {{ index .Options "Namespace" }}.oauth_state(auth_code);
comment on table {{ index .Options "Namespace" }}.oauth_state is 'stores metadata for oauth provider logins';
