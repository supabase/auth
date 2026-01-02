-- Add token_endpoint_auth_method column to oauth_clients table
-- This stores the authentication method used at the token endpoint:
-- - 'none' for public clients (PKCE only)
-- - 'client_secret_basic' for confidential clients (HTTP Basic Auth)
-- - 'client_secret_post' for confidential clients (POST body)

-- Create enum for token endpoint auth method
do $$ begin
    create type {{ index .Options "Namespace" }}.oauth_token_endpoint_auth_method as enum('none', 'client_secret_basic', 'client_secret_post');
exception
    when duplicate_object then null;
end $$;

-- Add token_endpoint_auth_method column with a default value based on client_type
-- This uses a CASE expression to set the correct default based on existing client_type
alter table {{ index .Options "Namespace" }}.oauth_clients
    add column if not exists token_endpoint_auth_method {{ index .Options "Namespace" }}.oauth_token_endpoint_auth_method;

-- Update existing rows to have the correct token_endpoint_auth_method based on client_type
update {{ index .Options "Namespace" }}.oauth_clients
set token_endpoint_auth_method = case
    when client_type = 'public' then 'none'::{{ index .Options "Namespace" }}.oauth_token_endpoint_auth_method
    else 'client_secret_basic'::{{ index .Options "Namespace" }}.oauth_token_endpoint_auth_method
end
where token_endpoint_auth_method is null;

-- Now make the column NOT NULL since all rows have values
alter table {{ index .Options "Namespace" }}.oauth_clients
    alter column token_endpoint_auth_method set not null;
