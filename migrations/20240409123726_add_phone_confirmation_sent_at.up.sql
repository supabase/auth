-- Add phone_confirmation_sent_at column to users table
ALTER TABLE "auth"."users" ADD COLUMN IF NOT EXISTS "phone_confirmation_sent_at" timestamptz;

-- Update the trigger that checks empty timestamps
CREATE OR REPLACE FUNCTION "auth"."set_empty_timestamps_as_null"() RETURNS TRIGGER AS $$
BEGIN
  IF NEW."created_at" IS NOT NULL AND NEW."created_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."created_at" = NULL;
  END IF;
  IF NEW."updated_at" IS NOT NULL AND NEW."updated_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."updated_at" = NULL;
  END IF;
  IF NEW."confirmed_at" IS NOT NULL AND NEW."confirmed_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."confirmed_at" = NULL;
  END IF;
  IF NEW."confirmation_sent_at" IS NOT NULL AND NEW."confirmation_sent_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."confirmation_sent_at" = NULL;
  END IF;
  IF NEW."phone_confirmation_sent_at" IS NOT NULL AND NEW."phone_confirmation_sent_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."phone_confirmation_sent_at" = NULL;
  END IF;
  IF NEW."recovery_sent_at" IS NOT NULL AND NEW."recovery_sent_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."recovery_sent_at" = NULL;
  END IF;
  IF NEW."email_change_sent_at" IS NOT NULL AND NEW."email_change_sent_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."email_change_sent_at" = NULL;
  END IF;
  IF NEW."phone_change_sent_at" IS NOT NULL AND NEW."phone_change_sent_at"::timestamptz = 'epoch'::timestamptz THEN
    NEW."phone_change_sent_at" = NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql; 