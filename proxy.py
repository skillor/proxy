from proxy_tcp_udp import ProxyTCPUDP
from proxy_http import ProxyHttp
from dns_resolver import init_dns_resolver, resolve_hostname


def main(host='127.0.0.1', remotes=('127.0.0.1:8080',), custom_dns: list = None):
    init_dns_resolver(custom_dns)
    for remote in remotes:
        protocol = remote.find('://')
        if protocol == -1:
            protocol = 'tcp'
        else:
            protocol = remote[:protocol]
            remote = remote[len(protocol) + 3:]
        s = remote.split(':')
        if protocol in ['tcp', 'udp']:
            t = ProxyTCPUDP(host, resolve_hostname(':'.join(s[:-1])), int(s[-1]), protocol)
        elif protocol in ['http', 'https']:
            t = ProxyHttp(host, resolve_hostname(':'.join(s[:-1])), int(s[-1]), protocol)
        else:
            raise Exception('unknown protocol: ' + protocol)
        t.start()

    while True:
        cmd = input('$ ')
        if cmd == 'q' or cmd == 'quit':
            exit(0)


if __name__ == '__main__':
    main(
        host='127.0.0.1',
        remotes=(
            # 'udp://127.0.0.1:8080',
            # 'tcp://127.0.0.1:8080',
            'http://www.httpvshttps.com:80',
            'https://www.httpvshttps.com:443',
        ),
        # custom_dns=['8.8.8.8'],
    )
