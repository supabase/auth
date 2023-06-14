

alter table saml_relay_states
  add column if not exists flow_state_id uuid references flow_states(id);
