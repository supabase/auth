alter table {{ index .Options "Namespace" }}.mfa_factors
    add column if not exists is_passkey boolean not null default false,
    add column if not exists web_authn_credential_id bytea null;

create index if not exists mfa_factors_user_passkey_idx
    on {{ index .Options "Namespace" }}.mfa_factors (user_id)
    where is_passkey is true;

create table if not exists {{ index .Options "Namespace" }}.passkey_challenges (
    id uuid primary key,
    user_id uuid null references {{ index .Options "Namespace" }}.users(id) on delete cascade,
    web_authn_session_data jsonb null,
    ip_address inet not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

comment on table {{ index .Options "Namespace" }}.passkey_challenges is 'auth: stores metadata about passkey sign-in challenges';
comment on column {{ index .Options "Namespace" }}.passkey_challenges.web_authn_session_data is 'WebAuthn session data for validating passkey challenges';
