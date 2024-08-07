alter table {{ index .Options "Namespace" }}.mfa_factors drop constraint if exists mfa_factors_phone_key;
do $$
begin
    if exists (
         select 1
         from pg_indexes
         where indexname = 'unique_verified_phone_factor'
         and schemaname = '{{ index .Options "Namespace" }}'
    ) then
        execute 'alter index {{ index .Options "Namespace" }}.unique_verified_phone_factor rename to unique_phone_factor_per_user';
    end if;
end $$;
