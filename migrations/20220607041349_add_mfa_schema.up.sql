-- auth.backups definition

DROP TYPE IF EXISTS factor_type;
CREATE TYPE factor_type AS ENUM('phone', 'webauthn', 'email')
CREATE TABLE IF NOT EXISTS auth.mfa_challenge(
       id VARCHAR(256)
       auth_factor_id VARCHAR(256)
       created_at timestamptz
       CONSTRAINT mfa_challenge_pkey PRIMARY KEY (id)
)

comment on table auth.mfa_challenges is 'Auth: stores data of Multi Factor Authentication Requests';


-- auth.factors definition

CREATE TABLE IF NOT EXISTS auth.mfa_factors(
       id VARCHAR(256)
       factor_simple_name VARCHAR(256)
       factor_type factor_type
       enabled BOOLEAN
       created_at timestamptz
       updated_at timestamptz
       totp_email VARCHAR(256)
       totp_phone VARCHAR(256)
       webauthn_public_key_bytes VARCHAR(256)
       webauthn_credential_id VARCHAR(256)
       CONSTRAINT mfa_factors_pkey PRIMARY KEY(id)
)

comment on table auth.factors is 'Auth: stores Multi Factor Authentication factor data';



-- auth.challenge definition
CREATE TABLE IF NOT EXISTS auth.mfa_backup_codes(
       user_id VARCHAR(256)
       created_at timestamptz
       backup_code VARCHAR(32)
       valid BOOLEAN
       time_used timestamptz
)

comment on table auth.backup_codes is 'Auth: stores backup codes for Multi Factor Authentication';
