alter table {{ index .Options "Namespace" }}.saml_relay_states add column if not exists flow_state_id uuid;
alter table {{ index .Options "Namespace" }}.saml_relay_states add constraint relat_state_flow_state_id_fkey foreign key(flow_state_id) references {{ index .Options "Namespace" }}.flow_state(id) on delete cascade;
