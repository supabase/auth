-- auth.mfa_recovery_codes definition
create table if not exists auth.mfa_recovery_codes(
       id uuid not null,
       user_id uuid not null,
       recovery_code varchar(32) not null,
       created_at timestamptz not null,
       verified_at timestamptz null,
       used_at timestamptz null,
       constraint mfa_recovery_codes_pkey primary key(id),
       constraint mfa_recovery_codes_user_id_recovery_code_unique unique(user_id, recovery_code),
       constraint mfa_recovery_codes_user_id_fkey foreign key(user_id) references auth.users(id) on delete cascade
);
comment on table auth.mfa_recovery_codes is 'auth: stores recovery codes for multi factor authentication';
