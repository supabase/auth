-- adds banned_until column

ALTER TABLE users
ADD COLUMN IF NOT EXISTS banned_until timestamptz NULL;
