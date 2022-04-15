-- adds banned_until column

ALTER TABLE auth.users
ADD COLUMN IF NOT EXISTS banned_until timestamptz NULL;
