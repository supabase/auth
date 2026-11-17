/* auth_migration: 20261028120000 */
-- Time step of the last TOTP code accepted for this factor. Used to reject a
-- code that was already used successfully, as required by RFC 6238 section 5.2.
alter table {{ index .Options "Namespace" }}.mfa_factors
    add column if not exists last_totp_step bigint default null;
