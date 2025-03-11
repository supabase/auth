-- Create types in the specified namespace using template variable
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type
        WHERE typname = 'factor_type'
        AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = '{{ index .Options "Namespace" }}')
    ) THEN
        CREATE TYPE {{ index .Options "Namespace" }}.factor_type AS ENUM ('totp', 'webauthn');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_type
        WHERE typname = 'factor_status'
        AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = '{{ index .Options "Namespace" }}')
    ) THEN
        CREATE TYPE {{ index .Options "Namespace" }}.factor_status AS ENUM ('unverified', 'verified');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_type
        WHERE typname = 'aal_level'
        AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = '{{ index .Options "Namespace" }}')
    ) THEN
        CREATE TYPE {{ index .Options "Namespace" }}.aal_level AS ENUM ('aal1', 'aal2', 'aal3');
    END IF;
END $$;

-- auth.mfa_factors definition
CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.mfa_factors (
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    friendly_name TEXT NULL,
    factor_type {{ index .Options "Namespace" }}.factor_type NOT NULL,
    status {{ index .Options "Namespace" }}.factor_status NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    secret TEXT NULL,
    CONSTRAINT mfa_factors_pkey PRIMARY KEY (id),
    CONSTRAINT mfa_factors_user_id_fkey FOREIGN KEY (user_id) REFERENCES {{ index .Options "Namespace" }}.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE {{ index .Options "Namespace" }}.mfa_factors IS 'auth: stores metadata about factors';

CREATE UNIQUE INDEX IF NOT EXISTS mfa_factors_user_friendly_name_unique ON {{ index .Options "Namespace" }}.mfa_factors (friendly_name, user_id) WHERE TRIM(friendly_name) <> '';

-- auth.mfa_challenges definition
CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.mfa_challenges (
    id UUID NOT NULL,
    factor_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ NULL,
    ip_address INET NOT NULL,
    CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id),
    CONSTRAINT mfa_challenges_auth_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES {{ index .Options "Namespace" }}.mfa_factors(id) ON DELETE CASCADE
);
COMMENT ON TABLE {{ index .Options "Namespace" }}.mfa_challenges IS 'auth: stores metadata about challenge requests made';

-- add factor_id and amr claims to session
CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.mfa_amr_claims (
    session_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    authentication_method TEXT NOT NULL,
    CONSTRAINT mfa_amr_claims_session_id_authentication_method_pkey UNIQUE (session_id, authentication_method),
    CONSTRAINT mfa_amr_claims_session_id_fkey FOREIGN KEY (session_id) REFERENCES {{ index .Options "Namespace" }}.sessions(id) ON DELETE CASCADE
);
COMMENT ON TABLE {{ index .Options "Namespace" }}.mfa_amr_claims IS 'auth: stores authenticator method reference claims for multi factor authentication';