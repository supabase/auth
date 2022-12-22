alter table {{ index .Options "Namespace" }}.mfa_amr_claims
  add column if not exists id uuid not null;

do $$
begin
  if not exists
     (select constraint_name
      from information_schema.check_constraints
      where constraint_schema = '{{ index .Options "Namespace" }}'
      and constraint_name = 'amr_id_pk')
  then
    alter table {{ index .Options "Namespace" }}.mfa_amr_claims add constraint amr_id_pk primary key(id);
  end if;
end $$;

create index if not exists user_id_created_at_idx on {{ index .Options "Namespace" }}.sessions (user_id, created_at);
create index if not exists factor_id_created_at_idx on {{ index .Options "Namespace" }}.mfa_factors (user_id, created_at);

