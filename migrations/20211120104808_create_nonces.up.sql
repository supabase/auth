CREATE TABLE IF NOT EXISTS auth.nonces
(
    instance_id uuid        NULL,
    id          uuid        NOT NULL,

    uri         text        NOT NULL,
    hostname    text        NOT NULL,

    namespace   varchar     NOT NULL,
    address     text        NOT NULL,
    nonce       varchar     NOT NULL,
    chain_id    varchar     NOT NULL,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    CONSTRAINT nonces_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS nonces_instance_id_idx ON auth.nonces USING btree (instance_id);
comment on table auth.nonces is 'Auth: Stored generated nonces used for validating Web3 login requests.';