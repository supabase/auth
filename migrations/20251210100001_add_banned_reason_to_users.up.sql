do $$ begin
    alter table only {{ index .Options "Namespace" }}.users
        add column if not exists banned_reason text null;
end $$;

comment on column {{ index .Options "Namespace" }}.users.banned_reason is 'Auth: Reason for user ban (e.g., SCIM_DEPROVISIONED)';
