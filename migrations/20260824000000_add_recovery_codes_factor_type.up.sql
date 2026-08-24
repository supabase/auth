/* auth_migration: 20260824000000 */
do $$ begin
    alter type {{ index .Options "Namespace" }}.factor_type add value 'recovery_codes';
exception
    when duplicate_object then null;
end $$;
