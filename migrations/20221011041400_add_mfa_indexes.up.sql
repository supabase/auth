create index if not exists refresh_token_session_id on {{ index .Options "Namespace" }}.refresh_tokens using btree(session_id);

-- Taken from: https://stackoverflow.com/questions/6801919/postgres-add-constraint-if-it-doesnt-already-exist
create or replace function create_constraint_if_not_exists (
    t_name text, c_name text, constraint_sql text
)
returns void AS
$$
begin
    -- Look for our constraint
    if not exists (select constraint_name
                   from information_schema.constraint_column_usage
                   where table_name = t_name  and constraint_name = c_name) then
        execute constraint_sql;
    end if;
end;

$$ language 'plpgsql'

alter table {{ index .Options "Namespace" }}.mfa_amr_claims
  add column if not exists id uuid not null;

create_constraint_if_not_exists("auth.mfa_amr_claims", "amr_id_pk", "ALTER TABLE auth.mfa_amr_claims add constraint amr_id_pk primary key(id)");
alter table {{ index .Options "Namespace" }}.mfa_amr_claims add constraint if not exists amr_id_pk primary key(id);

create index if not exists user_id_created_at_idx on {{ index .Options "Namespace" }}.sessions (user_id, created_at);
create index if not exists factor_id_created_at_idx on {{ index .Options "Namespace" }}.mfa_factors (user_id, created_at);

