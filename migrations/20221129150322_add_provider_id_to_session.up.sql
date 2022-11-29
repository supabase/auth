alter table only {{ index .Options "Namespace" }}.sessions
  add column if not exists provider_id text default null;

comment on column {{ index .Options "Namespace" }}.sessions.provider_id is 'Auth: ID of the provider on which basis this session was issued. Example: google, apple, facebook, twitter, email, phone, sso:<uuid>, ...';
