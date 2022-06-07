-- auth.backups definition

DROP TYPE IF EXISTS factor_type;
CREATE TYPE factor_type AS ENUM('phone', 'webauthn', 'email')
CREATE TABLE IF NOT EXISTS auth.mfa_challenge(
       id VARCHAR(256) NOT NULL,
       factor_id VARCHAR(256) NOT NULL,
       created_at timestamptz NULL,
       CONSTRAINT mfa_challenge_pkey PRIMARY KEY (id),
       CONSTRAINT mfa_challenge_auth_factor_id_fkey FOREIGN KEY (auth_factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE
)

comment on table auth.mfa_challenges is 'Auth: stores data of Multi Factor Authentication Requests';


-- auth.factors definition

CREATE TABLE IF NOT EXISTS auth.mfa_factors(
       id VARCHAR(256) NOT NULL,
       factor_simple_name VARCHAR(256) NUL,
       factor_type factor_type NOT NULL,
       enabled BOOLEAN NOT NULL,
       created_at timestamptz NOT NULL,
       updated_at timestamptz NULL,
       totp_email VARCHAR(256) NULL,
       totp_phone VARCHAR(256) NULL,
       webauthn_public_key_bytes VARCHAR(256) NULL,
       webauthn_credential_id VARCHAR(256) NULL,
       CONSTRAINT mfa_factors_pkey PRIMARY KEY(id)
)

comment on table auth.factors is 'Auth: stores Multi Factor Authentication factor data';



-- auth.challenge definition
CREATE TABLE IF NOT EXISTS auth.mfa_backup_codes(
       user_id uuid NOT NULL,
       created_at timestamptz NOT NULL,
       backup_code VARCHAR(32) NOT NULL,
       valid BOOLEAN NOT NULL,
       time_used timestamptz NULL,
       CONSTRAINT mfa_backup_codes_pkey PRIMARY KEY(user_id, backup_code)
       CONSTRAINT mfa_backup_codes FOREIGN KEY(user_id) REFERENCES auth.users(id) ON DELETE CASCADE
)

comment on table auth.backup_codes is 'Auth: stores backup codes for Multi Factor Authentication';
