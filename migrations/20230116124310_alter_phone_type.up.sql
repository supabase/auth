-- alter phone field column type to accomodate for soft deletion 

alter table auth.users
alter column phone type text,
alter column phone_change type text;
