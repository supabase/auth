alter table {{ index .Options "Namespace" }}.sessions add column if not exists provider_id text default null;
