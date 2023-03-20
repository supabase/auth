--  Introduces a tokens table to store tokens used by the /verify endpoint
create table if not exists {{ index .Options "Namespace" }}.tokens (
   id uuid not null,
   confirmation_token text null,
	confirmation_sent_at timestamptz NULL,
	recovery_token text NULL,
	recovery_sent_at timestamptz NULL,
	email_change_token text NULL,
	email_change_sent_at timestamptz NULL
);
