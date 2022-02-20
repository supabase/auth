CREATE TABLE auth.crypto_addresses
(
    instance_id uuid         NULL,
    id          uuid         NOT NULL,

    account_id  uuid         NOT NULL REFERENCES auth.users(id),
    address     varchar(255) NOT NULL UNIQUE,

    created_at  timestamptz  NULL DEFAULT now()
);

comment on table auth.nonces is 'Auth: Stored Cryptocurrency addresses for web3 authentication.';