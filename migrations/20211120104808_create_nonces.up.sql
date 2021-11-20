CREATE TABLE IF NOT EXISTS auth.nonces (
	instance_id uuid NULL,
	id uuid NOT NULL,
	hashed_ip varchar(255) NOT NULL,
	nonce varchar(255),
	created_at timestamptz NULL,
	expires_at timestamptz NULL,
	consumed_at timestamptz NULL,
	CONSTRAINT nonces_pkey PRIMARY KEY (id)
);
CREATE INDEX nonces_instance_id_idx ON auth.nonces USING btree (instance_id);
comment on table auth.nonces is 'Auth: Stored generated nonces used for validating Web3 login requests.';