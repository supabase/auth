do $$ begin
    create type user_verification as enum('preferred', 'required', 'discouraged');
exception
    when duplicate_object then null;
end $$;

do $$ begin
alter table {{ index .Options "Namespace" }}.mfa_factors add column public_key jsonb null;
alter table {{ index .Options "Namespace" }}.mfa_factors add column aaguid uuid null;

alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists webauthn_challenge text null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists user_verification user_verification null;
-- Need to add Allowed Credential IDs and Extensions. See: https://github.com/go-webauthn/webauthn/blob/master/webauthn/types.go#L181
end $$;
