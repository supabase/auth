-- Add scim_provider_id column to users table for provider isolation
alter table {{ index .Options "Namespace" }}.users 
add column if not exists scim_provider_id text null;

-- Create index for fast lookups by SCIM provider ID
create index if not exists users_scim_provider_id_idx 
    on {{ index .Options "Namespace" }}.users (scim_provider_id)
    where scim_provider_id is not null;