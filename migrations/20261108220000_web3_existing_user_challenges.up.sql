/* auth_migration: 20261108220000 */
create table {{ index .Options "Namespace" }}.web3_login_challenges (
    id uuid primary key,
    nonce_hash text not null unique,
    provider_id text not null,
    identity_id uuid not null,
    user_id uuid not null,
    chain text not null check (chain in ('ethereum', 'solana')),
    chain_id text not null,
    domain text not null,
    uri text not null,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    check (expires_at > created_at)
);
-- Deliberately no cascading FK: an identity deletion must not erase the
-- original binding or permit a replacement identity to reuse its challenge.
create index web3_login_challenges_expiry on {{ index .Options "Namespace" }}.web3_login_challenges (expires_at);
alter table {{ index .Options "Namespace" }}.web3_login_challenges enable row level security;
revoke all on {{ index .Options "Namespace" }}.web3_login_challenges from public;
