-- auth.oauth_state definition
create table if not exists {{ index .Options "Namespace" }}.oauth_state(
       id uuid primary key,
       supabase_auth_code text unique null constraint non_empty_code CHECK(length(supabase_auth_code)>0),
       code_challenge text null constraint non_empty_challenge CHECK(length(code_challenge)>0),
       provider_type text null,
       provider_access_token text null,
       provider_refresh_token text null,
       created_at timestamptz null,
       updated_at timestamptz null
);
create index idx_auth_code on {{ index .Options "Namespace" }}.oauth_state(supabase_auth_code);
comment on table {{ index .Options "Namespace" }}.oauth_state is 'stores metadata for oauth provider logins';
