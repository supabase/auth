-- adds encrypted_password_new

ALTER TABLE auth.users
ADD COLUMN IF NOT EXISTS encrypted_password_new varchar(255) default '';
