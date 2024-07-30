do $$ begin
alter table {{ index .Options "Namespace" }}.mfa_factors add column if not exists credential jsonb null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists session_data jsonb null;
end $$;
