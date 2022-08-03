CREATE TABLE auth.crypto_addresses
(
    instance_id uuid NULL,
    id          uuid         NOT NULL,

    account_id  uuid         NOT NULL REFERENCES auth.users (id),
    address     varchar(255) NOT NULL UNIQUE,
    provider    varchar(255) NOT NULL,

    created_at  timestamptz NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS crypto_addresses_instance_id_idx ON auth.crypto_addresses USING btree (instance_id);
comment on table auth.crypto_addresses is 'Auth: Stored Cryptocurrency addresses for web3 authentication.';
