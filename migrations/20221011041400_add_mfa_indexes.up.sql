create index if not exists refresh_token_session_id on {{ index .Options "Namespace" }}.refresh_tokens using btree(session_id);

alter table {{ index .Options "Namespace" }}.mfa_amr_claims
  add column if not exists id uuid not null,
  add constraint if not exists amr_id_pk primary key(id);

create index if not exists user_id_created_at_idx on {{ index .Options "Namespace" }}.sessions (user_id, created_at);
create index if not exists factor_id_created_at_idx on {{ index .Options "Namespace" }}.mfa_factors (user_id, created_at);

