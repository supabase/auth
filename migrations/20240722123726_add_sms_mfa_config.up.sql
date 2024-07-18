do $$ begin
    alter type factor_type add value 'sms';
exception
    when duplicate_object then null;
end $$;

alter table {{ index .Options "Namespace" }}.mfa_factors add column if not exists phone_number text unique default null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists sent_at timestamptz null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists otp_code text null;


-- Add constraint to ensure a user can only register one verified factor per phone number account
-- create unique index unique_verified_phone_factor on factors (user_id, phone_number) where factor_status = 'verified';
