BEGIN;

ALTER TABLE auth.users
  ALTER COLUMN confirmation_token SET DEFAULT '';
ALTER TABLE auth.users
  ALTER COLUMN recovery_token SET DEFAULT '';
ALTER TABLE auth.users
  ALTER COLUMN email_change_token_new SET DEFAULT '';
ALTER TABLE auth.users
  ALTER COLUMN email_change SET DEFAULT '';

COMMIT;
