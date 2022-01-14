-- adds ban_until column

ALTER TABLE auth.users
ADD COLUMN IF NOT EXISTS ban_until timestamptz NULL;
