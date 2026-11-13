-- Carry caller-supplied hook data across an external provider round trip.
--
-- The value is opaque to this service and lives only for the duration of the
-- flow: it is written here when the flow begins and read back when the provider
-- returns, so that hooks invoked while creating the user can see it.
/* auth_migration: 20260810000000 */
ALTER TABLE {{ index .Options "Namespace" }}.flow_state
    ADD COLUMN IF NOT EXISTS hook_data TEXT NULL;
