-- this change is relatively temporary
-- it is meant to keep database consistency guarantees until there is proper
-- introduction of account linking / merging / delinking APIs, at which point
-- rows in the users table will allow duplicates but with programmatic control

alter table only {{ index .Options "Namespace" }}.users
  add column if not exists is_sso_user boolean not null default false;

comment on column {{ index .Options "Namespace" }}.users.is_sso_user is 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';

do $$
begin
  alter table only {{ index .Options "Namespace" }}.users
    drop constraint if exists users_email_key;
exception
-- dependent object: https://www.postgresql.org/docs/current/errcodes-appendix.html
when SQLSTATE '2BP01' then
  raise notice 'Unable to drop users_email_key constraint due to dependent objects, please resolve this manually or SSO may not work';
end $$;
