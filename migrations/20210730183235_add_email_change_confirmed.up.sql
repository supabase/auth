-- adds email_change_confirmed

ALTER TABLE users
ADD COLUMN IF NOT EXISTS email_change_token_current varchar(255) null DEFAULT '', 
ADD COLUMN IF NOT EXISTS email_change_confirm_status smallint DEFAULT 0 CHECK (email_change_confirm_status >= 0 AND email_change_confirm_status <= 2);

ALTER TABLE "users" RENAME COLUMN "email_change_token" TO "email_change_token_new";
