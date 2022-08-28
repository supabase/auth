-- Add session_id column to refresh_tokens table
create table if not exists auth.sessions (
    id uuid not null,
    user_id uuid not null,
    created_at timestamptz null,
    updated_at timestamptz null,
    constraint sessions_pkey primary key (id),
    constraint sessions_user_id_fkey foreign key (user_id) references auth.users(id) on delete cascade
);
comment on table auth.sessions is 'Auth: Stores session data associated to a user.';

alter table auth.refresh_tokens
add column if not exists session_id uuid null;

do $$
begin
  if not exists(select *
    from information_schema.constraint_column_usage
    where table_schema = 'auth' and table_name='sessions' and constraint_name='refresh_tokens_session_id_fkey')
  then
      alter table "auth"."refresh_tokens" add constraint refresh_tokens_session_id_fkey foreign key (session_id) references auth.sessions(id) on delete cascade;
  end if;
END $$;
