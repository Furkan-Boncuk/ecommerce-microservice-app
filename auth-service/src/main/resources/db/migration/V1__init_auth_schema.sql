create table if not exists users (
    id uuid primary key,
    email varchar(255) not null unique,
    password varchar(255) not null,
    role varchar(32) not null,
    enabled boolean not null default true,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp
);
