DO $$ BEGIN
    -- Check if the current user owns the type, otherwise skip alteration
    IF EXISTS (
        SELECT 1
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'auth'
        AND t.typname = 'factor_type'
        AND pg_has_role(current_user, (SELECT rolname FROM pg_roles WHERE oid = t.typowner), 'USAGE')
    ) THEN
        BEGIN
            ALTER TYPE auth.factor_type ADD VALUE 'phone';
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END;
    ELSE
        RAISE NOTICE 'Skipping ALTER TYPE auth.factor_type: current user does not own the type';
    END IF;
END $$;

ALTER TABLE auth.mfa_factors ADD COLUMN IF NOT EXISTS phone TEXT UNIQUE DEFAULT NULL;
ALTER TABLE auth.mfa_challenges ADD COLUMN IF NOT EXISTS otp_code TEXT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS unique_verified_phone_factor ON auth.mfa_factors (user_id, phone);