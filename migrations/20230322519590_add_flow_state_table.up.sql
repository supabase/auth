-- see: https://stackoverflow.com/questions/7624919/check-if-a-user-defined-type-already-exists-in-postgresql/48382296#48382296
do $$ begin
    create type code_challenge_method as enum('s256', 'plain');
exception
    when duplicate_object then null;
end $$;
create table if not exists {{ index .Options "Namespace" }}.flow_state(
       id uuid primary key,
       user_id uuid null,
       auth_code text not null,
       code_challenge_method code_challenge_method not null,
       code_challenge text not null,
       provider_type text not null,
       provider_access_token text null,
       provider_refresh_token text null,
       created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
       organization_id uuid null,
       project_id uuid null,
       CONSTRAINT fk_organization_id FOREIGN KEY (organization_id) REFERENCES {{ index .Options "Namespace" }}.organizations(id) ON DELETE CASCADE,
        CONSTRAINT fk_project_id FOREIGN KEY (project_id) REFERENCES {{ index .Options "Namespace" }}.projects(id) ON DELETE CASCADE
);
create index if not exists idx_auth_code on {{ index .Options "Namespace" }}.flow_state(auth_code);
comment on table {{ index .Options "Namespace" }}.flow_state is 'stores metadata for pkce logins';
CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON {{ index .Options "Namespace" }}.flow_state FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER prevent_organization_project_null BEFORE INSERT OR UPDATE ON {{ index .Options "Namespace" }}.flow_state FOR EACH ROW EXECUTE FUNCTION prevent_organization_project_null();
CREATE TRIGGER prevent_change_organization_project BEFORE UPDATE ON {{ index .Options "Namespace" }}.flow_state FOR EACH ROW EXECUTE FUNCTION prevent_change_organization_project();