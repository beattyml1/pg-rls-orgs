create schema org;
set search_path = org;



-- Tables --
create table org.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    owner_id uuid references auth.users not null
);
ALTER TABLE org.organizations ENABLE ROW LEVEL SECURITY;

create table org.org_sso_connection (
    id uuid primary key default gen_random_uuid(),
    saml_provider_id uuid references auth.saml_providers,
    sso_domain_id uuid references auth.sso_domains
);
ALTER TABLE org.org_sso_connection ENABLE ROW LEVEL SECURITY;

create table org.org_roles (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid null references organizations,
    label text not null,
    description text
);
ALTER TABLE org.org_roles ENABLE ROW LEVEL SECURITY;

create table org.permissions ( 
    id uuid primary key default gen_random_uuid(),
    key text not null unique,
    label text not null,
    description text
);
ALTER TABLE org.permissions ENABLE ROW LEVEL SECURITY;

create table org.role_permissions (
    permission_id uuid primary key references permissions,
    role_id uuid primary key references org_roles
);
ALTER TABLE org.role_permissions ENABLE ROW LEVEL SECURITY;

create table org.org_users (
    organization_id uuid primary key references org.organizations,
    user_id uuid primary key references auth.users
);
ALTER TABLE org_users ENABLE ROW LEVEL SECURITY;

create table org.org_user_roles (
    organization_id uuid primary key references organizations,
    user_id uuid primary key references auth.users,
    role_id uuid primary key references org_roles
);
ALTER TABLE org_user_roles ENABLE ROW LEVEL SECURITY;

create table resource_group_types (
    id uuid primary key default gen_random_uuid(),
    key text not null unique,
    label text not null,
    description text
);
ALTER TABLE resource_group_types ENABLE ROW LEVEL SECURITY;

create table org.resource_groups (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references organizations,
    type_id uuid not null references resource_group_types,
    label text not null,
    description text
);
ALTER TABLE resource_groups ENABLE ROW LEVEL SECURITY;

create table org.resource_level_roles (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid null references organizations,
    label text not null,
    description text
);
ALTER TABLE resource_level_roles ENABLE ROW LEVEL SECURITY;

create table org.resource_group_role_permissions (
    permission_id uuid primary key references permissions,
    role_id uuid primary key references resource_level_roles
);
ALTER TABLE resource_group_role_permissions ENABLE ROW LEVEL SECURITY;

create table org.org_user_resource_level_roles (
    organization_id uuid primary key references organizations,
    user_id uuid primary key references auth.users,
    role_id uuid primary key references resource_level_roles,
    resource_group_id uuid primary key references resource_groups
);
ALTER TABLE org_user_resource_level_roles ENABLE ROW LEVEL SECURITY;

create table org.groups(
    id uuid primary key default gen_random_uuid(),
    organization_id uuid null references organizations,
    label text not null,
    description text
);
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;

create table org.group_resource_roles (
    group_id uuid primary key references org.groups,
    resource_group_id uuid primary key references org.resource_groups,
    role_id uuid primary key references resource_level_roles
);
ALTER TABLE group_resource_roles ENABLE ROW LEVEL SECURITY;

create table org.group_roles (
    group_id uuid primary key references org.groups,
    role_id uuid primary key references org_roles
);
ALTER TABLE group_roles ENABLE ROW LEVEL SECURITY;

create table group_users (
    group_id uuid primary key references org.groups,
    user_id uuid primary key references auth.users
);
ALTER TABLE group_users ENABLE ROW LEVEL SECURITY;




-- Functions --
create function permissions_for_user(uid uuid, oid uuid) returns table(key text) as $$
   begin
       select p.key
       from permissions p
       inner join role_permissions rp on p.id = rp.permission_id
       inner join org_roles o on o.id = rp.role_id
       inner join org_user_roles our on o.id = our.role_id
       where our.user_id = uid and our.organization_id = oid
       union
       select p.key
       from permissions p
       inner join role_permissions rp on p.id = rp.permission_id
       inner join org_roles o on o.id = rp.role_id
       inner join group_roles gr on o.id = gr.role_id
       inner join groups g on gr.group_id = g.id
       inner join group_users gu on g.id = gu.group_id
       where gu.user_id = uid and g.organization_id = oid;
   end;
$$ language plpgsql;

create function current_permissions(org_id uuid) returns table(key text) as $$
   begin
    select key from permissions_for_user(auth.uid(), org_id);
   end;
$$ language plpgsql;

create function has_permission(permission text, org_id uuid) returns boolean as $$
   begin
    return exists(select key from current_permissions(org_id) where key = permission);
   end;
$$ language plpgsql;

create function resource_permissions_for_user(uid uuid, oid uuid, rg_id uuid) returns table(key text) as $$
   begin
       select p.key
       from permissions p
       inner join resource_group_role_permissions rp on p.id = rp.permission_id
       inner join resource_level_roles o on o.id = rp.role_id
       inner join org_user_resource_level_roles our on o.id = our.role_id
       where our.user_id = uid and our.organization_id = oid and our.resource_group_id = rg_id
       union
       select p.key
       from permissions p
       inner join resource_group_role_permissions rp on p.id = rp.permission_id
       inner join resource_level_roles o on o.id = rp.role_id
       inner join group_resource_roles gr on o.id = gr.role_id
       inner join groups g on gr.group_id = g.id
       inner join group_users gu on g.id = gu.group_id
       where gu.user_id = uid and g.organization_id = oid and gr.resource_group_id = rg_id;
   end;
$$ language plpgsql;

create function current_resource_permissions(org_id uuid, res_group_id uuid) returns table(key text) as $$
   begin
    select key from resource_permissions_for_user(auth.uid(), org_id, res_group_id);
   end;
$$ language plpgsql;

create function has_resource_permission(permission text, org_id uuid, res_group_id uuid) returns boolean as $$
   begin
    return exists(
        select key
        from current_resource_permissions(org_id, res_group_id)
        where key = permission
    );
   end;
$$ language plpgsql;



-- Base Policies --
create policy permissions_select on permissions as permissive 
    for select using (true);
create policy resource_group_types_select on resource_group_types as permissive 
    for select using (true);
create policy org_roles_select_no_org  on org_roles as permissive 
    for select using (organization_id is null);
create policy resource_level_roles_select_no_org on resource_level_roles as permissive 
    for select using (organization_id is null);

