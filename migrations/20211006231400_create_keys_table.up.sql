CREATE TABLE auth.asymmetric_keys (
    id bigserial NOT NULL,
    user_id uuid NOT NULL,
	key VARCHAR ( 150 ) UNIQUE NOT NULL,
	algorithm VARCHAR (15) NOT NULL,
	main bool DEFAULT false NOT NULL,
	challenge_token uuid NOT NULL,
	challenge_token_issued_at timestamptz NOT NULL,
	challenge_token_expires_at timestamptz NOT NULL,
	challenge_passed bool DEFAULT false NOT NULL,

    created_at timestamptz NULL,
	updated_at timestamptz NULL,
	CONSTRAINT asymmetric_keys_pkey PRIMARY KEY (id),
	CONSTRAINT asymmetric_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
