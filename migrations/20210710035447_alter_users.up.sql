-- alter user schema

ALTER TABLE {{ index .Options "Namespace" }}.users 
ADD COLUMN IF NOT EXISTS phone VARCHAR(15) NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS phone_confirmed_at timestamptz NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS phone_change VARCHAR(15) NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS phone_change_token VARCHAR(255) NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS phone_change_sent_at timestamptz NULL DEFAULT NULL;

-- Make unique pair of phone and organization_id
DO $$
BEGIN
  IF NOT EXISTS(SELECT *
    FROM information_schema.constraint_column_usage
    WHERE table_schema = '{{ index .Options "Namespace" }}' and table_name='users' and constraint_name='users_phone_organization_id_unique')
  THEN
      ALTER TABLE "{{ index .Options "Namespace" }}"."users" ADD CONSTRAINT users_phone_organization_id_unique UNIQUE (phone, organization_id);
  END IF;
END $$;


--Make unique pair of phone and project_id if project_id is not null

DO $$
BEGIN
  IF NOT EXISTS(SELECT *
    FROM information_schema.constraint_column_usage
    WHERE table_schema = '{{ index .Options "Namespace" }}' and table_name='users' and constraint_name='users_phone_project_id_unique')
  THEN
      ALTER TABLE "{{ index .Options "Namespace" }}"."users" ADD CONSTRAINT users_phone_project_id_unique UNIQUE (phone, project_id);
  END IF;
END $$;




DO $$
BEGIN
  IF NOT EXISTS(SELECT *
    FROM information_schema.columns
    WHERE table_schema = '{{ index .Options "Namespace" }}' and table_name='users' and column_name='email_confirmed_at')
  THEN
      ALTER TABLE "{{ index .Options "Namespace" }}"."users" RENAME COLUMN "confirmed_at" TO "email_confirmed_at";
  END IF;
END $$;

