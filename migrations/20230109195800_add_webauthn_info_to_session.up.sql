-- update sessions
alter table only {{ index .Options "Namespace" }}.sessions
  add column if not exists webauthn_registration_session jsonb;

alter table only {{ index .Options "Namespace" }}.sessions
  add column if not exists webauthn_login_session jsonb;

alter table only {{ index .Options "Namespace" }}.sessions
  add column if not exists webauthn_configuration jsonb;

comment on column {{ index .Options "Namespace" }}.sessions.webauthn_registration_session is 'Auth: json storing webauthn created on enrollment';
comment on column {{ index .Options "Namespace" }}.sessions.webauthn_login_session is 'Auth: json storing webauthn metadata created on verification';
comment on column {{ index .Options "Namespace" }}.sessions.webauthn_configuration is 'Auth: Webauthn metadata for overall session created when user enrolls a device';
