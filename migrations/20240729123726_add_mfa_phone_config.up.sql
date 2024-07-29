do $$ begin
    alter type {{ index .Options "Namespace" }}.factor_type add value 'phone';
exception
    when duplicate_object then null;
end $$;


alter table {{ index .Options "Namespace" }}.mfa_factors add column if not exists phone text unique default null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists sent_at timestamptz null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists otp_code text null;

create index if not exists idx_sent_at on {{ index .Options "Namespace" }}.mfa_challenges(sent_at);

create unique index if not exists unique_verified_phone_factor on {{ index .Options "Namespace" }}.mfa_factors (user_id, phone) where status = 'verified';
