CREATE TABLE auth.nonces (
	instance_id uuid NULL,
	id uuid NOT NULL,
	
	hashed_ip varchar(255) NOT NULL,

	uri text NOT NULL,
	wallet_address text NOT NULL,
	chain_id integer NOT NULL,

	created_at timestamptz NULL,
	expires_at timestamptz NULL,
	CONSTRAINT nonces_pkey PRIMARY KEY (id)
);
CREATE INDEX nonces_instance_id_idx ON auth.nonces USING btree (instance_id);
comment on table auth.nonces is 'Auth: Stored generated nonces used for validating Web3 login requests.';