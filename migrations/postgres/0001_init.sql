create extension if not exists btree_gist;

do
$$
begin
    execute format('alter database %I set timezone = %L', current_database(), 'UTC');
end
$$;

create domain inet_port as int4 check (value between 1 and 65535);
create domain inet_mtu as int2 check (value between 1280 and 1500);
create domain wg_key as bytea check (length(value) = 32);
create domain host_ip as inet check (masklen(value) = case family(value) when 4 then 32 else 128 end);
create domain dns_name as text check (
    length(value) <= 253
        and value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
        and value !~ '(^|\.)[0-9]+$'
);
create domain linux_ifname as text check (
    length(value) between 1 and 15
        and value !~ '[/:[:space:]]'
        and value not in ('.', '..')
);
create domain iface_name as text check (value ~ '^[a-zA-Z0-9_-]{1,15}$');
create domain vpn_protocol as text check (value in ('wireguard'));
create domain vpn_transport as text check (value in ('udp', 'tcp'));

create table hosts (
    id int8 generated always as identity primary key,
    name text not null unique check (name <> ''),
    created_at timestamptz not null default now()
);

create table host_ssh (
    host_id int8 primary key references hosts (id) on delete cascade,
    ssh_addr host_ip,
    ssh_name dns_name,
    port inet_port not null default 22,
    username text not null default 'root' check (username ~ '^[a-z_][a-z0-9_-]{0,31}$'),
    host_key bytea not null check (length(host_key) > 0),
    --
    check ((ssh_addr is null) <> (ssh_name is null))
);

create table vpn_servers (
    id int8 generated always as identity primary key,
    host_id int8 not null references hosts (id) on delete restrict,
    protocol vpn_protocol not null,
    transport vpn_transport not null,
    interface_name iface_name not null,
    listen_port inet_port not null,
    endpoint_addr host_ip,
    endpoint_name dns_name,
    endpoint_port inet_port,
    --
    ipv4_network cidr check (family(ipv4_network) = 4 and masklen(ipv4_network) between 8 and 30),
    ipv6_network cidr check (family(ipv6_network) = 6 and masklen(ipv6_network) between 48 and 120),
    ipv4_address inet check (family(ipv4_address) = 4 and masklen(ipv4_address) = 32),
    ipv6_address inet check (family(ipv6_address) = 6 and masklen(ipv6_address) = 128),
    --
    nat_ipv4 bool not null,
    nat_ipv6 bool not null,
    egress_interface linux_ifname,
    client_isolation bool not null default true,
    client_dns_servers host_ip[] not null default '{}',
    client_dns_search dns_name[] not null default '{}',
    created_at timestamptz not null default now(),
    --
    unique (id, protocol),
    unique (host_id, transport, listen_port),
    unique (host_id, interface_name),
    exclude using gist (host_id with =, ipv4_network inet_ops with &&),
    exclude using gist (host_id with =, ipv6_network inet_ops with &&),
    check (protocol <> 'wireguard' or transport = 'udp'),
    check ((endpoint_addr is null) <> (endpoint_name is null)),
    check (ipv4_network is not null or ipv6_network is not null),
    check ((ipv4_network is null) = (ipv4_address is null)),
    check ((ipv6_network is null) = (ipv6_address is null)),
    check (ipv4_address <<= ipv4_network
        and ipv4_address <> set_masklen(ipv4_network::inet, 32)
        and ipv4_address <> set_masklen(broadcast(ipv4_network), 32)),
    check (ipv6_address <<= ipv6_network
        and ipv6_address <> set_masklen(ipv6_network::inet, 128)),
    check (not nat_ipv4 or ipv4_network is not null),
    check (not nat_ipv6 or ipv6_network is not null),
    check (array_position(client_dns_servers, null) is null),
    check (array_position(client_dns_search, null) is null),
    --
    check (cardinality(client_dns_search) = 0 or cardinality(client_dns_servers) > 0)
);

create table wg_servers (
    server_id int8 primary key,
    protocol vpn_protocol not null default 'wireguard' check (protocol = 'wireguard'),
    private_key wg_key not null,
    public_key wg_key not null unique,
    mtu inet_mtu,
    client_mtu inet_mtu,
    --
    foreign key (server_id, protocol) references vpn_servers (id, protocol) on delete cascade
);

create table server_apply_state (
    server_id int8 primary key references vpn_servers (id) on delete cascade,
    applied_sha256 bytea check (length(applied_sha256) = 32),
    applied_at timestamptz,
    last_error text,
    last_error_at timestamptz,
    --
    check ((applied_sha256 is null) = (applied_at is null)),
    check ((last_error is null) = (last_error_at is null))
);

create table vpn_clients (
    id int8 generated always as identity primary key,
    server_id int8 not null,
    protocol vpn_protocol not null,
    name iface_name not null,
    ipv4_address inet check (family(ipv4_address) = 4 and masklen(ipv4_address) = 32),
    ipv6_address inet check (family(ipv6_address) = 6 and masklen(ipv6_address) = 128),
    tunnel_networks cidr[] not null default '{0.0.0.0/0,::/0}'
        check (cardinality(tunnel_networks) > 0 and array_position(tunnel_networks, null) is null),
    enabled bool not null default true,
    created_at timestamptz not null default now(),
    --
    foreign key (server_id, protocol) references vpn_servers (id, protocol) on delete restrict,
    unique (id, server_id, protocol),
    unique (server_id, name),
    unique (server_id, ipv4_address),
    unique (server_id, ipv6_address),
    check (ipv4_address is not null or ipv6_address is not null)
);

create table wg_clients (
    client_id int8 primary key,
    server_id int8 not null,
    protocol vpn_protocol not null default 'wireguard' check (protocol = 'wireguard'),
    private_key wg_key not null,
    public_key wg_key not null,
    preshared_key wg_key not null,
    persistent_keepalive int4 default 25 check (persistent_keepalive between 1 and 65535),
    --
    foreign key (client_id, server_id, protocol)
        references vpn_clients (id, server_id, protocol) on delete cascade,
    unique (server_id, public_key)
);

create function client_address_ok(addr inet, net cidr, server_addr inet) returns bool
    language sql
    immutable
return (addr is null) = (net is null) and (addr is null or (
        addr <<= net
    and addr <> server_addr
    and addr <> set_masklen(net::inet, masklen(addr))
    and (family(net) = 6 or addr <> set_masklen(broadcast(net), 32))
));

create function vpn_clients_check_address()
    returns trigger
    language plpgsql as
$$
declare
    s vpn_servers;
begin
    select * into s from vpn_servers where id = new.server_id for share;
    if not found then
        return new;
    end if;
    if not (
        client_address_ok(new.ipv4_address, s.ipv4_network, s.ipv4_address)
        and
        client_address_ok(new.ipv6_address, s.ipv6_network, s.ipv6_address)
    ) then
        raise exception 'client % address does not fit server % networks', new.name, s.id
            using errcode = 'check_violation';
    end if;
    return new;
end
$$;

create trigger check_address
before insert or update of server_id, ipv4_address, ipv6_address
on vpn_clients
for each row
execute function vpn_clients_check_address();

create function vpn_servers_check_client_addresses()
    returns trigger
    language plpgsql as
$$
declare
    ok bool;
begin
    ok := !exists (
        select
        from vpn_clients c
        where c.server_id = new.id
            and not (
                client_address_ok(c.ipv4_address, new.ipv4_network, new.ipv4_address)
                and
                client_address_ok(c.ipv6_address, new.ipv6_network, new.ipv6_address)
            )
    );
    if !ok then
        raise exception 'server % networks do not fit its clients addresses', new.id
            using errcode = 'check_violation';
    end if;
    return new;
end
$$;

create trigger check_client_addresses
after update of ipv4_network, ipv6_network, ipv4_address, ipv6_address
on vpn_servers
for each row
execute function vpn_servers_check_client_addresses();
