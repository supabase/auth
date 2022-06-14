-- See: https://stackoverflow.com/questions/7624919/check-if-a-user-defined-type-already-exists-in-postgresql/48382296#48382296
DO $$ BEGIN
    CREATE TYPE factor_type AS ENUM('phone', 'webauthn');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- auth.mfa_factors definition
CREATE TABLE IF NOT EXISTS auth.mfa_factors(
       id VARCHAR(256) NOT NULL,
       user_id uuid NOT NULL,
       factor_simple_name VARCHAR(256) NULL,
       factor_type factor_type NOT NULL,
       enabled BOOLEAN NOT NULL,
       created_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL,
       secret_key VARCHAR(256) NOT NULL,
       CONSTRAINT mfa_factors_pkey PRIMARY KEY(id),
       CONSTRAINT mfa_factors FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
comment on table auth.mfa_factors is 'Auth: stores Multi Factor Authentication factor data';

-- auth.mfa_challenges definition
CREATE TABLE IF NOT EXISTS auth.mfa_challenges(
       id VARCHAR(256) NOT NULL,
       factor_id VARCHAR(256) NOT NULL,
       created_at timestamptz NOT NULL,
       CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id),
       CONSTRAINT mfa_challenges_auth_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE
);
comment on table auth.mfa_challenges is 'Auth: stores data of Multi Factor Authentication Requests';

-- auth.mfa_backup_codes definition
CREATE TABLE IF NOT EXISTS auth.mfa_backup_codes(
       user_id uuid NOT NULL,
       backup_code VARCHAR(32) NOT NULL,
       valid BOOLEAN NOT NULL,
       created_at timestamptz NOT NULL,
       used_at timestamptz NOT NULL,
       CONSTRAINT mfa_backup_codes_pkey PRIMARY KEY(user_id, backup_code),
       CONSTRAINT mfa_backup_codes FOREIGN KEY(user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
comment on table auth.mfa_backup_codes is 'Auth: stores backup codes for Multi Factor Authentication';

-- Add MFA toggle on Users table
ALTER TABLE auth.users
ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT FALSE;
