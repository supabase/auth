-- add partial unique indices to confirmation_token, recovery_token, email_change_token_current, email_change_token_new, phone_change_token, reauthentication_token

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS confirmation_token_idx ON auth.users USING btree (confirmation_token) WHERE confirmation_token != '';
-- CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS recovery_token_idx ON auth.users USING btree (recovery_token) WHERE recovery_token != '';
-- CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS email_change_token_current_idx ON auth.users USING btree (email_change_token_current) WHERE email_change_token_current != '';
-- CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS email_change_token_new_idx ON auth.users USING btree (email_change_token_new) WHERE email_change_token_new != '';
-- CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS reauthentication_token_idx ON auth.users USING btree (reauthentication_token) WHERE reauthentication_token != '';
