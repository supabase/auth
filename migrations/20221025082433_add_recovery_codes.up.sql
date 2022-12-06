-- auth.mfa_recovery_codes definition
alter type factor_type rename to factor_type_old;
-- https://blog.yo1.dog/updating-enum-values-in-postgresql-the-safe-and-easy-way/
create type factor_type as enum('totp', 'webauthn', 'recovery_code');
alter table {{ index .Options "Namespace" }}.mfa_factors alter column factor_type type factor_type using factor_type::text::factor_type;
drop type factor_type_old;


create table if not exists {{ index .Options "Namespace" }}.mfa_recovery_codes(
       id uuid not null,
       factor_id uuid not null,
       recovery_code varchar(32) not null,
       created_at timestamptz not null,
       used_at timestamptz null,
       constraint mfa_recovery_codes_pkey primary key(id),
       constraint mfa_recovery_codes_factor_id_fkey foreign key(factor_id) references {{ index .Options "Namespace" }}.mfa_factors(id) on delete cascade
);
create unique index only_one_recovery_factor_per_user on {{ index .Options "Namespace" }}.mfa_factors(user_id,factor_type) where factor_type = 'recovery_code' and status = 'verified';
comment on table {{ index .Options "Namespace" }}.mfa_recovery_codes is 'auth: stores recovery codes for multi factor authentication';
