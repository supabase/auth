/* auth_migration: 20261013000000 */
-- Session that approved the authorization; its AAL/AMR is inherited by the OAuth session.
alter table {{ index .Options "Namespace" }}.oauth_authorizations
    add column if not exists session_id uuid null references {{ index .Options "Namespace" }}.sessions(id) on delete set null;
