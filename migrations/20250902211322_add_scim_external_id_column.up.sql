-- Add scim_external_id column to users table
alter table {{ index .Options "Namespace" }}.users 
add column if not exists scim_external_id text null;

-- Create index for fast lookups by SCIM external ID
create index if not exists users_scim_external_id_idx 
    on {{ index .Options "Namespace" }}.users (scim_external_id)
    where scim_external_id is not null;