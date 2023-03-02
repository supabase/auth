-- auth.oauth_state definition
create table if not exists {{ index .Options "Namespace" }}.oauth_state(
       id uuid primary key,
       supabase_auth_code text unique null,
       code_challenge text null,
       provider_type text null,
       provider_access_token text null,
       provider_refresh_token text null,
       created_at timestamptz null,
       updated_at timestamptz null
);
create index idx_auth_code on {{ index .Options "Namespace" }}.oauth_state(supabase_auth_code);
comment on table {{ index .Options "Namespace" }}.oauth_state is 'stores metadata for oauth provider logins';
