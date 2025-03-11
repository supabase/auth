-- previous backfill migration left last_sign_in_at to be null, which broke some projects

do $$
BEGIN
UPDATE {{ index .Options "Namespace" }}.identities
  SET last_sign_in_at = '2022-11-25'
    WHERE 
        last_sign_in_at IS NULL AND
        created_at = '2022-11-25' AND
        updated_at = '2022-11-25' AND
        provider = 'email' AND
        id::text = user_id::text;
EXCEPTION 
    WHEN OTHERS THEN
        RAISE NOTICE 'Error in backfill migration: %', SQLERRM;
END $$;
