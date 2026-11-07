/* auth_migration: 20261031100001 */
-- Client Identifier URL for clients using a Client ID Metadata Document.
-- Each URL maps to a single active client row.
alter table if exists {{ index .Options "Namespace" }}.oauth_clients
  add column if not exists client_id_url text null;

do $$ begin
  alter table {{ index .Options "Namespace" }}.oauth_clients
    add constraint oauth_clients_client_id_url_length check (char_length(client_id_url) <= 2048);
exception
  when duplicate_object then null;
end $$;

create unique index if not exists oauth_clients_client_id_url_idx
  on {{ index .Options "Namespace" }}.oauth_clients (client_id_url)
  where client_id_url is not null and deleted_at is null;
