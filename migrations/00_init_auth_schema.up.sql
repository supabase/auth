-- update trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();  -- Set the updated_at to the current timestamp
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- auth.organization_roles definition

CREATE TYPE {{ index .Options "Namespace" }}."organization_roles" AS ENUM (
  'admin',
  'client'
);

-- auth.role_permissions definition
CREATE TYPE {{ index .Options "Namespace" }}."role_permissions" AS ENUM (
);

-- auth.projects definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.projects (
	id uuid UNIQUE NOT NULL,
	name varchar(255) NOT NULL UNIQUE,
	description text NULL,
	rate_limits jsonb NOT NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT projects_pkey PRIMARY KEY (id)
);
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
comment on table {{ index .Options "Namespace" }}.projects is 'Auth: Stores project data.';

-- auth.users definition

CREATE OR REPLACE FUNCTION prevent_change_organization_project()
RETURNS TRIGGER AS $$
BEGIN
	-- If organization_id is already set and the new organization_id is different from the old one, raise an exception
	IF OLD.organization_id IS NOT NULL AND NEW.organization_id != OLD.organization_id THEN
		RAISE EXCEPTION 'organization_id cannot be changed, it is immutable';
	END IF;

	-- If project_id is already set and the new project_id is different from the old one, raise an exception
	IF OLD.project_id IS NOT NULL AND NEW.project_id != OLD.project_id THEN
		RAISE EXCEPTION 'project_id cannot be changed, it is immutable';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_set_project_id()
RETURNS TRIGGER AS $$
BEGIN
	-- If organization_id is already set and the new project_id is different from the old one(either an existing project_id(update) or a null project_id(set)), raise an exception
	-- When creating a user, first set the project_id and then the organization_id -> organization_role(admin). If organization_id is set first, the user is a client and cannot been binded to a project.
	IF OLD.organization_id IS NOT NULL AND NEW.project_id != OLD.project_id THEN
		RAISE EXCEPTION 'project_id cannot be set when organization_id is already set. If project_id is not set and organization_id is set this means the user is a client and not an admin.';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_organization_role()
RETURNS TRIGGER AS $$
BEGIN
	-- If the organization_role is an admin, both project_id and organization_id should be set
	IF NEW.organization_role = 'admin' THEN
		IF NEW.project_id IS NULL THEN
			RAISE EXCEPTION 'project_id cannot be null when organization_role is admin';
		END IF;
		IF NEW.organization_id IS NULL THEN
			RAISE EXCEPTION 'organization_id cannot be null when organization_role is admin';
		END IF;
	END IF;

	-- If the organization_role is updated from admin to client, raise an exception
	IF OLD.organization_role = 'admin' AND NEW.organization_role = 'client' THEN
		RAISE EXCEPTION 'organization_role cannot be changed from admin to client';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_organization_project_null()
RETURNS TRIGGER AS $$
BEGIN
	-- Prevent creating a user with both organization_id and project_id null
	IF NEW.organization_id IS NULL AND NEW.project_id IS NULL THEN
		RAISE EXCEPTION 'organization_id and project_id cannot be null';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION set_admin_organization_role()
RETURNS TRIGGER AS $$
BEGIN
	-- Set the user as an admin if the OLD.project_id is not null and the NEW.organization_id is not null
	IF OLD.project_id IS NOT NULL AND NEW.organization_id IS NOT NULL THEN
		NEW.organization_role = 'admin';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.users (
	instance_id uuid NULL,
	id uuid NOT NULL UNIQUE,
	aud varchar(255) NULL,
	"role" varchar(255) NULL,
	email varchar(255) NULL,
	encrypted_password varchar(255) NULL,
	confirmed_at timestamptz NULL,
	invited_at timestamptz NULL,
	confirmation_token varchar(255) NULL,
	confirmation_sent_at timestamptz NULL,
	recovery_token varchar(255) NULL,
	recovery_sent_at timestamptz NULL,
	email_change_token varchar(255) NULL,
	email_change varchar(255) NULL,
	email_change_sent_at timestamptz NULL,
	last_sign_in_at timestamptz NULL,
	raw_app_meta_data jsonb NULL,
	raw_user_meta_data jsonb NULL,
	is_super_admin bool NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	organization_id uuid NULL,
	project_id uuid NULL,
	organization_role {{ index .Options "Namespace" }}.organization_roles DEFAULT 'client',
	CONSTRAINT users_project_id_fkey FOREIGN KEY (project_id) REFERENCES {{ index .Options "Namespace" }}.projects(id),
	CONSTRAINT users_email_organization_id_unique UNIQUE (email, organization_id), -- unique email per organization
	CONSTRAINT users_email_project_id_unique UNIQUE (email, project_id), -- unique email per project
	CONSTRAINT users_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS users_instance_id_email_idx ON {{ index .Options "Namespace" }}.users USING btree (instance_id, email);
CREATE INDEX IF NOT EXISTS users_instance_id_idx ON {{ index .Options "Namespace" }}.users USING btree (instance_id);
comment on table {{ index .Options "Namespace" }}.users is 'Auth: Stores user login data within a secure schema.';
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER prevent_change_organization_project BEFORE UPDATE ON {{ index .Options "Namespace" }}.users FOR EACH ROW EXECUTE FUNCTION prevent_change_organization_project();
CREATE TRIGGER prevent_set_project_id BEFORE UPDATE ON {{ index .Options "Namespace" }}.users FOR EACH ROW EXECUTE FUNCTION prevent_set_project_id();
CREATE TRIGGER update_organization_role BEFORE UPDATE ON {{ index .Options "Namespace" }}.users FOR EACH ROW EXECUTE FUNCTION update_organization_role();
CREATE TRIGGER prevent_organization_project_null BEFORE INSERT OR UPDATE ON {{ index .Options "Namespace" }}.users FOR EACH ROW EXECUTE FUNCTION prevent_organization_project_null();
CREATE TRIGGER set_admin_organization_role BEFORE INSERT OR UPDATE ON {{ index .Options "Namespace" }}.users FOR EACH ROW EXECUTE FUNCTION set_admin_organization_role();

-- auth.organizations definition
CREATE OR REPLACE FUNCTION prevent_fkey_change()
RETURNS TRIGGER AS $$
BEGIN
	-- Check if the field has been updated
	IF NEW.admin_id != OLD.admin_id THEN
		RAISE EXCEPTION 'admin_id cannot be changed';
	END IF;

	-- Check if the field has been updated
	IF NEW.project_id != OLD.project_id THEN
		RAISE EXCEPTION 'project_id cannot be changed';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.organizations (
	id uuid UNIQUE NOT NULL,
	project_id uuid NOT NULL,
	admin_id uuid UNIQUE NOT NULL,
	name varchar(255) NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT organizations_project_id_fkey FOREIGN KEY (project_id) REFERENCES {{ index .Options "Namespace" }}.projects(id) on delete cascade,
	CONSTRAINT organizations_admin_id_fkey FOREIGN KEY (admin_id) REFERENCES {{ index .Options "Namespace" }}.users(id),
	CONSTRAINT organizations_pkey PRIMARY KEY (id)
);
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER prevent_fkey_change BEFORE UPDATE ON {{ index .Options "Namespace" }}.organizations FOR EACH ROW EXECUTE FUNCTION prevent_fkey_change();
comment on table {{ index .Options "Namespace" }}.organizations is 'Auth: Stores organization data.';

DO $$
BEGIN
  IF NOT EXISTS(SELECT *
    FROM information_schema.constraint_column_usage
    WHERE table_schema = '{{ index .Options "Namespace" }}' and table_name='users' and constraint_name='users_organization_id_fkey')
  THEN
      ALTER TABLE {{ index .Options "Namespace" }}.users ADD CONSTRAINT users_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES {{ index .Options "Namespace" }}.organizations(id);
  END IF;
END $$;

-- auth.smtp_configs_organization definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.smtp_configs_organizations (
	id serial UNIQUE NOT NULL,
	organization_id uuid NOT NULL,
	domain varchar(255) NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT smtp_configs_organizations_pkey PRIMARY KEY (id),
	CONSTRAINT smtp_configs_organizations_id_fkey FOREIGN KEY (organization_id) REFERENCES {{ index .Options "Namespace" }}.organizations(id) on delete cascade,
	CONSTRAINT smtp_configs_domain_organization_id_unique UNIQUE (domain, organization_id)
);
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.smtp_configs_organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
comment on table {{ index .Options "Namespace" }}.smtp_configs_organizations is 'Auth: Stores SMTP configurations for organizations.';

-- auth.smtp_configs_project definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.smtp_configs_project (
	id bigserial UNIQUE NOT NULL,
	project_id uuid UNIQUE NOT NULL,
	domain varchar(255) NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT smtp_configs_project_pkey PRIMARY KEY (id),
	CONSTRAINT smtp_configs_project_id_fkey FOREIGN KEY (project_id) REFERENCES {{ index .Options "Namespace" }}.projects(id) on delete cascade,
	CONSTRAINT smtp_configs_domain_project_id_unique UNIQUE (domain, project_id)
);
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.smtp_configs_project FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
comment on table {{ index .Options "Namespace" }}.smtp_configs_project is 'Auth: Stores SMTP configurations for projects.';
-- organization_roles_permissions definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.organization_roles_permissions (
	id serial unique NOT NULL,
	organization_role {{ index .Options "Namespace" }}.organization_roles NOT NULL,
	permissions {{ index .Options "Namespace" }}.role_permissions NOT NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT organization_roles_permissions_organization_role_permission_unique UNIQUE (organization_role, permissions),
	CONSTRAINT organization_roles_permissions_pkey PRIMARY KEY (id)
);
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.organization_roles_permissions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
comment on table {{ index .Options "Namespace" }}.organization_roles_permissions is 'Auth: Stores permissions for organization roles.';

-- auth.refresh_tokens definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.refresh_tokens (
	instance_id uuid NULL,
	id bigserial NOT NULL,
	"token" varchar(255) NULL,
	user_id varchar(255) NULL,
	revoked bool NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS refresh_tokens_instance_id_idx ON {{ index .Options "Namespace" }}.refresh_tokens USING btree (instance_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_instance_id_user_id_idx ON {{ index .Options "Namespace" }}.refresh_tokens USING btree (instance_id, user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_token_idx ON {{ index .Options "Namespace" }}.refresh_tokens USING btree (token);
comment on table {{ index .Options "Namespace" }}.refresh_tokens is 'Auth: Store of tokens used to refresh JWT tokens once they expire.';
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.refresh_tokens FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- auth.instances definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.instances (
	id uuid NOT NULL,
	uuid uuid NULL,
	raw_base_config text NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT instances_pkey PRIMARY KEY (id)
);
comment on table {{ index .Options "Namespace" }}.instances is 'Auth: Manages users across multiple sites.';
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.instances FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- auth.audit_log_entries definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.audit_log_entries (
	instance_id uuid NULL,
	id uuid NOT NULL,
	payload json NULL,
	created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS audit_logs_instance_id_idx ON {{ index .Options "Namespace" }}.audit_log_entries USING btree (instance_id);
comment on table {{ index .Options "Namespace" }}.audit_log_entries is 'Auth: Audit trail for user actions.';

-- auth.schema_migrations definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.schema_migrations (
	"version" varchar(255) NOT NULL,
	CONSTRAINT schema_migrations_pkey PRIMARY KEY ("version")
);
comment on table {{ index .Options "Namespace" }}.schema_migrations is 'Auth: Manages updates to the auth system.';
		
-- Gets the User ID from the request cookie
create or replace function {{ index .Options "Namespace" }}.uid() returns uuid as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid;
$$ language sql stable;

-- Gets the User ID from the request cookie
create or replace function {{ index .Options "Namespace" }}.role() returns text as $$
  select nullif(current_setting('request.jwt.claim.role', true), '')::text;
$$ language sql stable;
