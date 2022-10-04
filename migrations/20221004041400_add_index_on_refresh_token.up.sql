create index if not exists refresh_token_session_id on {{ index .Options "Namespace" }}.refresh_tokens using btree (session_id);
