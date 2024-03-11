do $$ begin
   create type flow_type as enum('code', 'pkce');
exception
    when duplicate_object then null;
end $$;

do $$
begin
   alter table {{ index .Options "Namespace" }}.flow_state
   add column if not exists flow_type flow_type not null default 'code';

end
$$;
