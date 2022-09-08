-- See: https://stackoverflow.com/questions/7624919/check-if-a-user-defined-type-already-exists-in-postgresql/48382296#48382296
DO $$ BEGIN
    CREATE TYPE factor_type AS ENUM('totp', 'webauthn');
    CREATE TYPE factor_status AS ENUM('disabled', 'unverified', 'verified');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- auth.mfa_factors definition
CREATE TABLE IF NOT EXISTS auth.mfa_factors(
       id text NOT NULL,
       user_id uuid NOT NULL,
       friendly_name text NULL,
       factor_type factor_type NOT NULL,
       status factor_status NOT NULL,
       created_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL,
       secret_key text NOT NULL,
       UNIQUE(user_id, friendly_name),
       CONSTRAINT mfa_factors_pkey PRIMARY KEY(id),
       CONSTRAINT mfa_factors_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
comment on table auth.mfa_factors is 'Auth: stores metadata about factors';

-- auth.mfa_challenges definition
CREATE TABLE IF NOT EXISTS auth.mfa_challenges(
       id text NOT NULL,
       factor_id text NOT NULL,
       created_at timestamptz NOT NULL,
       verified_at timestamptz  NULL,
       CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id),
       CONSTRAINT mfa_challenges_auth_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE
);
comment on table auth.mfa_challenges is 'Auth: stores metadata about challenge requests made';


-- Add factor_id to sessions
ALTER TABLE auth.sessions ADD COLUMN IF NOT EXISTS factor_id text NULL;
ALTER TABLE auth.sessions ADD COLUMN IF NOT EXISTS aal integer NULL;

-- Add factor_id and AMR claims to session
CREATE TABLE IF NOT EXISTS auth.mfa_amr_claims(
    id uuid NOT NULL,
    session_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    sign_in_method text NOT NULL,
    CONSTRAINT mfa_amr_claims_session_id_pkey UNIQUE(session_id, id),
    CONSTRAINT mfa_amr_claims_session_id_fkey FOREIGN KEY(session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE
);
comment on table auth.mfa_amr_claims is 'Auth: stores authenticator method reference claims for multi factor authentication';
