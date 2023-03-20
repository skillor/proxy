import os
try:
    import parse as parser
except ModuleNotFoundError:
    cwd = os.path.dirname(os.path.realpath(__file__))
    parse_path = os.path.join(cwd, 'parse.py')
    config_path = os.path.join(cwd, 'config.ini')
    if not os.path.exists(parse_path):
        print('creating', parse_path)
        with open(parse_path, 'w', encoding='utf-8') as f:
            f.write('''def parse(data, proxy):
    print('{}[{}://{}:{}]{}'.format(proxy.origin, proxy.protocol, proxy.id, proxy.port, data))
    return data
''')
        import parse as parser

    if not os.path.exists(config_path):
        print('creating', config_path)
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write('''HOST=127.0.0.1:8080
PROXY=http://www.httpvshttps.com:80
; HOST=0.0.0.0
; PROXY=udp://217.160.58.45:4004
; PROXY=tcp://217.160.58.45:4004
; DNS=8.8.8.8
''')
        print('stopping, change your', config_path, 'and restart the script')
        quit()

from urllib3.util import connection
import urllib3.exceptions

import requests
from flask import Flask, request, make_response
import logging

import socket
import threading

from importlib import reload

DNS_CACHE = {}
DNS_RESOLVER = None


def init_dns_resolver(custom_dns):
    if custom_dns is None or len(custom_dns) == 0:
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

RUNNING_I = 0


def get_id():
    global RUNNING_I
    RUNNING_I += 1
    return RUNNING_I - 1


def parse(data, proxy):
    try:
        reload(parser)
        return parser.parse(data, proxy)
    except Exception as e:
        print('{}[{}://{}:{}]{}'.format(proxy.origin, proxy.protocol, proxy.id, proxy.port, e))
    return data


class ProxyWare:
    def __init__(self, host, port, protocol, origin='unknown'):
        self.id = get_id()
        self.port = port
        self.host = host
        self.address = (host, port)
        self.address_str = '{}:{}'.format(host, port)
        self.protocol = protocol
        self.origin = origin

    def setup(self):
        print("{}[{}://:{}] setting up".format(self.origin, self.protocol, self.port))


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ['WERKZEUG_RUN_MAIN'] = 'true'


class ProxyHttp(ProxyWare, threading.Thread):
    def __init__(self, from_host, from_port, to_host, to_port, protocol):
        threading.Thread.__init__(self)
        self.daemon = True
        ProxyWare.__init__(self, to_host, to_port, protocol, 'proxy')
        self.g2p = ProxyWare(from_host, from_port, protocol, 'client')
        self.p2s = ProxyWare(to_host, to_port, protocol, 'server')
        self.app = Flask(__name__)
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

        @self.app.route('/', methods=['GET', 'POST'])
        @self.app.route('/<path:text>', methods=['GET', 'POST'])
        def all_routes(text=''):
            req_params = dict(request.args)
            req_headers = dict(request.headers)
            if self.g2p.address_str == self.p2s.address_str:
                remote_hostname = req_headers['Host']
            else:
                remote_hostname = self.p2s.address_str
                req_headers['Host'] = self.p2s.address_str
            url = '{}://{}/{}'.format('https' if request.is_secure else 'http', remote_hostname, text)
            query_url = url + ('?' + '&'.join(['{}={}'.format(k, v) for k, v in req_params.items()])
                               if bool(req_params)
                               else '')
            req_info = {
                'url': query_url,
                'cookies': dict(request.cookies),
                'headers': req_headers,
                'form': dict(request.form),
                'data': request.data,
            }
            req_info = parse(req_info, self.g2p)
            requester = {
                'GET': requests.get,
                'POST': requests.post,
            }[request.method]
            req_data = req_info['form'] if bool(request.form) else request.data
            res = requester(url,
                            params=req_params,
                            data=req_data,
                            headers=req_info['headers'],
                            cookies=req_info['cookies'],
                            verify=False,
                            stream=True)
            res_data = res.raw.read()
            res_info = {
                'url': res.url,
                'cookies': dict(res.cookies),
                'headers': dict(res.headers),
                'data': res_data,
                'status_code': res.status_code,
            }
            res_info = parse(res_info, self.p2s)
            resp = make_response(res_data, res.status_code, res_info['headers'])
            return resp

    def run(self):
        ProxyHttp.setup(self)
        if self.protocol == 'https':
            self.app.run(host=self.g2p.host, port=self.g2p.port, ssl_context='adhoc')
        else:
            self.app.run(host=self.g2p.host, port=self.g2p.port)


class Proxy2Server(ProxyWare, threading.Thread):
    def __init__(self, host, port, protocol):
        threading.Thread.__init__(self)
        self.daemon = True
        ProxyWare.__init__(self, host, port, protocol, 'server')
        self.game = None
        if self.protocol == 'udp':
            pass
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(self.address)

    def run(self):
        if self.protocol == 'udp':
            pass
        else:
            while True:
                data = self.socket.recv(4096)
                if data:
                    data = parse(data, self)
                    self.game.conn.sendall(data)


class Game2Proxy(ProxyWare, threading.Thread):
    def __init__(self, host, port, protocol):
        threading.Thread.__init__(self)
        self.daemon = True
        ProxyWare.__init__(self, host, port, protocol, 'client')
        self.server = None
        if self.protocol == 'udp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(self.address)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.address)
            self.socket.listen(1)

            self.conn, addr = self.socket.accept()

    def run(self):
        if self.protocol == 'udp':
            client_address = None
            while True:
                data, address = self.socket.recvfrom(4096)
                if client_address is None:
                    client_address = address
                if address == self.server.address:
                    data = parse(data, self.server)
                    self.socket.sendto(data, client_address)
                    client_address = None
                else:
                    client_address = address
                    data = parse(data, self)
                    self.socket.sendto(data, self.server.address)
        else:
            while True:
                data = self.conn.recv(4096)
                if data:
                    data = parse(data, self)
                    self.server.socket.sendall(data)


class ProxyTCPUDP(ProxyWare, threading.Thread):
    def __init__(self, from_host, from_port, to_host, to_port, protocol):
        threading.Thread.__init__(self)
        self.daemon = True
        ProxyWare.__init__(self, to_host, to_port, protocol, 'proxy')
        self.from_host = from_host
        self.from_port = from_port
        self.protocol = protocol
        self.g2p = None
        self.p2s = None

    def setup(self):
        ProxyWare.setup(self)
        self.g2p = Game2Proxy(self.from_host, self.from_port, self.protocol)
        self.p2s = Proxy2Server(self.host, self.port, self.protocol)
        self.g2p.server = self.p2s
        self.p2s.game = self.g2p

        self.g2p.start()
        self.p2s.start()

    def run(self):
        if self.protocol == 'udp':
            self.setup()
        else:
            while True:
                self.setup()


def host_to_ip_port(h):
    protocol = h.find('://')
    if protocol == -1:
        protocol = 'tcp'
    else:
        protocol = h[:protocol]
        h = h[len(protocol) + 3:]
    s = h.split(':')
    port = -1
    try:
        port = int(s[-1])
    except ValueError:
        pass
    return ':'.join(s[:-1]), port, protocol


def main(host=('127.0.0.1',), proxy=('127.0.0.1:8080',), dns=tuple()):
    """
    :param host: list of hosts
    :param proxy: list of proxy server to create
    :param dns: list of custom dns server ['8.8.8.8']
    """
    host_count = len(host)
    dns = list(dns)
    init_dns_resolver(dns)
    for i, remote in enumerate(proxy):
        local_host, local_port, _ = host_to_ip_port(host[min(host_count - 1, i)])
        remote_host, remote_port, protocol = host_to_ip_port(remote)
        if local_port < 0:
            local_port = remote_port
        if protocol in ['tcp', 'udp']:
            t = ProxyTCPUDP(local_host, local_port, resolve_hostname(remote_host), remote_port, protocol)
        elif protocol in ['http', 'https']:
            t = ProxyHttp(local_host, local_port, resolve_hostname(remote_host), remote_port, protocol)
        else:
            raise Exception('unknown protocol: ' + protocol)
        t.start()

    while True:
        cmd = input('$ ')
        if cmd == 'q' or cmd == 'quit':
            exit(0)


def parse_config(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()
    d = {}
    for line in lines:
        if line == '' or line.startswith(';'):
            continue
        s = line.split('=')
        k, v = s[0].lower(), '='.join(s[1:])
        if k in d:
            d[k].append(v)
        else:
            d[k] = [v]
    return d


if __name__ == '__main__':
    cwd = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(cwd, 'config.ini')
    main(**parse_config(config_path))
