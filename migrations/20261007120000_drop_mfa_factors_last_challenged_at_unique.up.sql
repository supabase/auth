/* auth_migration: 20261007120000 */
-- last_challenged_at is a per-factor timestamp; it must not be unique across
-- all factors (concurrent challenges from different users collide, #2854).
alter table {{ index .Options "Namespace" }}.mfa_factors
    drop constraint if exists mfa_factors_last_challenged_at_key;
