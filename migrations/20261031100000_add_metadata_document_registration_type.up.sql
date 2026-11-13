/* auth_migration: 20261031100000 */
-- Clients identified by a Client ID Metadata Document URL instead of being registered
do $$ begin
    alter type {{ index .Options "Namespace" }}.oauth_registration_type add value 'metadata_document';
exception
    when duplicate_object then null;
end $$;
