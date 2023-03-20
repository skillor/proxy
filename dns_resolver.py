from urllib3.util import connection

DNS_CACHE = {}
DNS_RESOLVER = None


def init_dns_resolver(custom_dns):
    if custom_dns is None:
        return
    global DNS_RESOLVER
    if DNS_RESOLVER is None:
        import dns.resolver
        DNS_RESOLVER = dns.resolver.Resolver(configure=False)
    DNS_RESOLVER.nameservers = custom_dns


def resolve_hostname(hostname):
    if DNS_RESOLVER is None:
        return hostname

    if hostname in DNS_CACHE:
        return DNS_CACHE[hostname]

    _t = DNS_RESOLVER.resolve(hostname, 'A')[0].to_text()
    DNS_CACHE[hostname] = _t
    return _t


_orig_create_connection = connection.create_connection


def patched_create_connection(address, *args, **kwargs):
    hostname, port = address
    hostname = resolve_hostname(hostname)
    return _orig_create_connection((hostname, port), *args, **kwargs)


connection.create_connection = patched_create_connection
