-- Add resource column to sessions table to bind OAuth access tokens to the
-- RFC 8707 resource indicator granted at authorization time.
-- This is nullable to avoid issues with existing sessions.
/* auth_migration: 20261030120000 */
alter table if exists {{ index .Options "Namespace" }}.sessions
  add column if not exists resource text null;

-- Same length limit as oauth_authorizations.resource
/* auth_migration: 20261030120000 */
do $$ begin
  alter table {{ index .Options "Namespace" }}.sessions
    add constraint sessions_resource_length check (char_length(resource) <= 2048);
exception
  when duplicate_object then null;
end $$;
