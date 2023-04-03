alter table {{index .Options "Namespace" }}.flow_state
add column authentication_method text not null;
