-- adds deleted_at column to auth.users 

alter table auth.users 
add column if not exists deleted_at timestamptz null;
