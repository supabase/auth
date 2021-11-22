-- adds parent column

ALTER TABLE auth.refresh_tokens
ADD COLUMN IF NOT EXISTS parent varchar(255) NULL,
ADD CONSTRAINT refresh_tokens_token_unique UNIQUE ("token"),
ADD CONSTRAINT refresh_tokens_parent_fkey FOREIGN KEY (parent) REFERENCES auth.refresh_tokens("token");

CREATE INDEX IF NOT EXISTS refresh_tokens_parent_idx ON refresh_tokens USING btree (parent);
