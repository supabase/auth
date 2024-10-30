-- adds identities table 

CREATE OR REPLACE FUNCTION prevent_set_both_organization_and_project()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.organization_id IS NOT NULL AND NEW.project_id IS NOT NULL THEN
        RAISE EXCEPTION 'Cannot set both organization_id and project_id';
    END IF;

    IF OLD.organization_id IS NOT NULL AND NEW.project_id IS NOT NULL THEN
        RAISE EXCEPTION 'Cannot set both organization_id and project_id. Organization_id is already set';
    END IF;

    IF OLD.project_id IS NOT NULL AND NEW.organization_id IS NOT NULL THEN
        RAISE EXCEPTION 'Cannot set both organization_id and project_id. Project_id is already set';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.identities (
    id text NOT NULL,
    user_id uuid NOT NULL,
    identity_data JSONB NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamptz NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    organization_id uuid NULL,
    project_id uuid NULL,
    CONSTRAINT identities_pkey PRIMARY KEY (provider, id),
    CONSTRAINT identities_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES {{ index .Options "Namespace" }}.organizations(id),
    CONSTRAINT identities_project_id_fkey FOREIGN KEY (project_id) REFERENCES {{ index .Options "Namespace" }}.projects(id),
    CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES {{ index .Options "Namespace" }}.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE {{ index .Options "Namespace" }}.identities is 'Auth: Stores identities associated to a user.';
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.identities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER prevent_change_organization_project BEFORE UPDATE ON {{ index .Options "Namespace" }}.identities FOR EACH ROW EXECUTE FUNCTION prevent_change_organization_project();
CREATE TRIGGER prevent_set_both_organization_and_project BEFORE UPDATE ON {{ index .Options "Namespace" }}.identities FOR EACH ROW EXECUTE FUNCTION prevent_set_both_organization_and_project();