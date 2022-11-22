-- Taken from: https://stackoverflow.com/questions/6801919/postgres-add-constraint-if-it-doesnt-already-exist
create or replace function create_auth_constraint_if_not_exists (
    c_name text, constraint_sql text
)
returns void AS
$$
begin
    -- Modify only auth constraint
    if not exists ( select constraint_name
                from    information_schema.check_constraints
                where   constraint_schema = 'auth'
                  and   constraint_name = c_name
              )
    then
        execute constraint_sql;
    end if;
end;
$$
language 'plpgsql';

alter table {{ index .Options "Namespace" }}.mfa_amr_claims
  add column if not exists id uuid not null;

select create_auth_constraint_if_not_exists('amr_id_pk', 'alter table auth.mfa_amr_claims add constraint amr_id_pk primary key(id)');

create index if not exists user_id_created_at_idx on {{ index .Options "Namespace" }}.sessions (user_id, created_at);
create index if not exists factor_id_created_at_idx on {{ index .Options "Namespace" }}.mfa_factors (user_id, created_at);

