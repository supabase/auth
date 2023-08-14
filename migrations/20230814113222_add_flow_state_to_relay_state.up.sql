alter table {{ index .Options "Namespace" }}.saml_relay_states add column if not exists flow_state_id uuid;
