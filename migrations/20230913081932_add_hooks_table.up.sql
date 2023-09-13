-- auth.hooks definition

create table if not exists {{ index .Options "Namespace" }}.hooks(
    name text null,
    hook_uri text not null,
    secret text not null,
    extensibility_point text not null,
    metadata json  null,
    constraint extensibility_point_pkey primary key (extensibility_point)
);

comment on table {{ index .Options "Namespace" }}.hooks is 'Auth: Store of hook configuration - can be used to customize hooks for given extensibility points.';
