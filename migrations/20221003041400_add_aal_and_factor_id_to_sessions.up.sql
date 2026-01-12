-- add factor_id to sessions
 alter table {{ index .Options "Namespace" }}.sessions add column if not exists factor_id uuid null;
 alter table {{ index .Options "Namespace" }}.sessions add column if not exists aal aal_level null;
