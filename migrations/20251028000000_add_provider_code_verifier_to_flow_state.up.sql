-- Add provider_code_verifier column to flow_state table
-- This stores the code_verifier used for PKCE flow when this auth instance
-- acts as an OAuth client to another Supabase instance
alter table {{ index .Options "Namespace" }}.flow_state
add column if not exists provider_code_verifier text null;

comment on column {{ index .Options "Namespace" }}.flow_state.provider_code_verifier is 'stores the code verifier for PKCE when communicating with external OAuth providers';
