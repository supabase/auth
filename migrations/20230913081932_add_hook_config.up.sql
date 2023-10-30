-- auth.hooks definition

create table if not exists {{ index .Options "Namespace" }}.hook_config(
    id uuid not null,
    uri text not null,
    event_name text not null,
    secret text not null,
    extensibility_point text not null,
    request_schema jsonb not null,
    response_schema jsonb not null,
    metadata json  null,
    constraint extensibility_point_pkey primary key (extensibility_point),
    constraint event_name_charset_check check (event_name ~ '^[a-zA-Z0-9_]+$')
);


comment on table {{ index .Options "Namespace" }}.hook_config is 'Auth: Store of hook configuration - can be used to customize hooks for given extensibility points.';
