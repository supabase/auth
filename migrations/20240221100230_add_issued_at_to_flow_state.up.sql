alter table {{ index .Options "Namespace" }}.flow_state add column if not exists issued_at timestamptz null;
