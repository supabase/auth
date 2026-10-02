/* auth_migration: 20261002000000 */
create unique index if not exists scim_users_user_id_key
    on {{ index .Options "Namespace" }}.scim_users (sso_provider_id, user_id)
    where user_id is not null and deleted_at is null;
