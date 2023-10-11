-- auth.hooks definition

create table if not exists {{ index .Options "Namespace" }}.hook_config(
    id uuid not null,
    uri text not null,
    -- This is an array in order to allow for low downtime JWT secret rotation
    secret text[] not null,
    extensibility_point text not null,
    request_schema jsonb not null,
    response_schema jsonb not null,
    metadata json  null,
    constraint extensibility_point_pkey primary key (extensibility_point)
);

comment on table {{ index .Options "Namespace" }}.hook_config is 'Auth: Store of hook configuration - can be used to customize hooks for given extensibility points.';
