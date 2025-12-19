/* auth_migration: 20251203000000 */
revoke all on {{ index .Options "Namespace" }}.schema_migrations from postgres;
/* auth_migration: 20251203000000 */
grant select on {{ index .Options "Namespace" }}.schema_migrations to postgres with grant option;
