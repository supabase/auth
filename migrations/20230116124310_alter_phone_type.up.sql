-- alter phone field column type to accomodate for soft deletion 

do $$
begin
  alter table {{ index .Options "Namespace" }}.users
    alter column phone type text,
    alter column phone_change type text;
exception
  -- dependent object: https://www.postgresql.org/docs/current/errcodes-appendix.html
  when SQLSTATE '2BP01' then
    raise notice 'Unable to change data type of phone, phone_change columns due to dependent objects';
end $$;
