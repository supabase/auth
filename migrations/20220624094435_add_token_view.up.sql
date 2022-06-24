-- add encrypted_email column
alter table auth.users
add column encrypted_email varchar(255) generated always as (md5(email)) stored;
