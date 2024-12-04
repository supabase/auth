do $$ begin
  create type one_time_token_type as enum (
    'confirmation_token',
    'reauthentication_token',
    'recovery_token',
    'email_change_token_new',
    'email_change_token_current',
    'phone_change_token'
  );
exception
  when duplicate_object then null;
end $$;


do $$ begin
  create table if not exists {{ index .Options "Namespace" }}.one_time_tokens (
    id uuid primary key,
    user_id uuid not null references {{ index .Options "Namespace" }}.users on delete cascade,
    token_type one_time_token_type not null,
    token_hash text not null,
    relates_to text not null,
    created_at timestamp without time zone not null default now(),
    updated_at timestamp without time zone not null default now(),
    check (char_length(token_hash) > 0)
  );

  create index if not exists one_time_tokens_token_hash_hash_idx on {{ index .Options "Namespace" }}.one_time_tokens using hash (token_hash);
  create index if not exists one_time_tokens_relates_to_hash_idx on {{ index .Options "Namespace" }}.one_time_tokens using hash (relates_to);
  create unique index if not exists one_time_tokens_user_id_token_type_key on {{ index .Options "Namespace" }}.one_time_tokens (user_id, token_type);
end $$;
