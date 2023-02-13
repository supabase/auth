-- auth.oauth_state definition
create table if not exists {{ index .Options "Namespace" }}.oauth_state(
       id uuid primary key,
       internal_auth_code text null,
       hashed_code_challenge text null,
       provider_type text null,
       redirect_uri text null,
       created_at timestamptz null,
       updated_at timestamptz null,
);
comment on table {{ index .Options "Namespace" }}.oauth_state is 'stores metadata for oauth provider logins';
