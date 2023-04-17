alter table {{index .Options "Namespace" }}.flow_state
add column if not exists authentication_method text not null;
create index if not exists idx_user_id_auth_method on {{index .Options "Namespace" }}.flow_state (user_id, authentication_method);
