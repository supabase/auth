do $$ begin
    alter type {{ index .Options "Namespace" }}.factor_type add value 'phone';
exception
    when duplicate_object then null;
end $$;

-- Needed as the new 'sms' value must be committed before it can be used in the `mfa_factors` transaction
commit;

alter table {{ index .Options "Namespace" }}.mfa_factors add column if not exists phone text unique default null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists sent_at timestamptz null;
alter table {{ index .Options "Namespace" }}.mfa_challenges add column if not exists otp_code text null;

create unique index unique_verified_phone_factor on {{ index .Options "Namespace" }}.mfa_factors (user_id, phone) where status = 'verified';

alter table {{ index .Options "Namespace" }}.mfa_factors add constraint check_phone_number_required_for_phone_factor check (factor_type != 'phone' or (phone is not null and phone != ''));
