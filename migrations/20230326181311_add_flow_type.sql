-- alter flow_type schema

create type flow_type as enum('oauth', 'pkce_phone_signup', 'pkce_email_signup', 'pkce_recovery', 'pkce_email_change', 'pkce_invite', 'pkce_phone_change');

alter table {{index .Options "Namespace" }}.flow_type
add column flow_type flow_type not null;
