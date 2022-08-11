-- Add session_id column to refresh_tokens table
alter table auth.refresh_tokens
add column if not exists session_id uuid null;
