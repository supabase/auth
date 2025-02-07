-- Add nonces table for Web3 authentication
create table if not exists {{ index .Options "Namespace" }}.nonces (
    id uuid primary key,
    nonce text not null,
    address text not null,
    created_at timestamp with time zone not null default now(),
    expires_at timestamp with time zone not null,
    used boolean not null default false
);

-- Create index for nonce lookup
create index if not exists idx_nonces_nonce on {{ index .Options "Namespace" }}.nonces (nonce);

-- Create index for cleanup of expired nonces
create index if not exists idx_nonces_expires_at on {{ index .Options "Namespace" }}.nonces (expires_at);

-- Add comment on table
comment on table {{ index .Options "Namespace" }}.nonces is 'Stores nonces for Web3 authentication';

-- Add comments on columns
comment on column {{ index .Options "Namespace" }}.nonces.id is 'Unique identifier for the nonce record';
comment on column {{ index .Options "Namespace" }}.nonces.nonce is 'The actual nonce value used for authentication';
comment on column {{ index .Options "Namespace" }}.nonces.address is 'The wallet address that used this nonce (set after use)';
comment on column {{ index .Options "Namespace" }}.nonces.created_at is 'When this nonce was created';
comment on column {{ index .Options "Namespace" }}.nonces.expires_at is 'When this nonce expires';
comment on column {{ index .Options "Namespace" }}.nonces.used is 'Whether this nonce has been used';