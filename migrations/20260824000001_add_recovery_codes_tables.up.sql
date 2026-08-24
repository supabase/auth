-- Enforce exactly one recovery-codes factor per user.
/* auth_migration: 20260824000001 */
create unique index if not exists mfa_factors_user_recovery_codes_unique
    on {{ index .Options "Namespace" }}.mfa_factors (user_id) where factor_type = 'recovery_codes';

/* auth_migration: 20260824000001 */
create table if not exists {{ index .Options "Namespace" }}.mfa_recovery_code_sets (
    id uuid primary key,
    factor_id uuid not null unique references {{ index .Options "Namespace" }}.mfa_factors (id) on delete cascade,
    failed_verification_count integer not null default 0 check (failed_verification_count >= 0),
    verification_locked_until timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

/* auth_migration: 20260824000001 */
create table if not exists {{ index .Options "Namespace" }}.mfa_recovery_codes (
    id uuid primary key,
    mfa_recovery_code_set_id uuid not null references {{ index .Options "Namespace" }}.mfa_recovery_code_sets (id) on delete cascade,
    code_hash text not null,
    used_at timestamptz,
    created_at timestamptz not null default now()
);

/* auth_migration: 20260824000001 */
create index if not exists mfa_recovery_codes_set_id_idx
    on {{ index .Options "Namespace" }}.mfa_recovery_codes (mfa_recovery_code_set_id);
