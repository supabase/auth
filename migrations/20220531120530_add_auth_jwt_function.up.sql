-- add jwt function

comment on function uid() is 'Deprecated. Use jwt() -> ''sub'' instead.';
comment on function role() is 'Deprecated. Use jwt() -> ''role'' instead.';
comment on function email() is 'Deprecated. Use jwt() -> ''email'' instead.';

create or replace function jwt()
returns jsonb
language sql stable
as $$
  select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;
