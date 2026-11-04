do $$ begin

    alter table only {{ index .Options "Namespace" }}.saml_providers
        add column if not exists dedicated_scope boolean null;

end $$;
