alter table if exists {{ index .Options "Namespace" }}.sessions
  add column if not exists oauth_client_id uuid null references {{ index .Options "Namespace" }}.oauth_clients(id) on delete cascade;
