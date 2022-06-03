-- alter phone field column type to accomodate for soft deletion 

alter table auth.users
alter column phone type varchar(255),
alter column phone_change type varchar(255);
