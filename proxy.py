from urllib3.util import connection
import urllib3.exceptions

import requests
from flask import Flask, request, make_response
import logging
import os

import socket
import threading

import parse as parser
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
        self.protocol = protocol
        self.origin = origin

    def setup(self):
        print("{}[{}://:{}] setting up".format(self.origin, self.protocol, self.port))


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ['WERKZEUG_RUN_MAIN'] = 'true'


class ProxyHttp(ProxyWare, threading.Thread):
    def __init__(self, from_host, to_host, port, protocol):
        threading.Thread.__init__(self)
        self.daemon = True
        ProxyWare.__init__(self, to_host, port, protocol, 'proxy')
        self.g2p = ProxyWare(from_host, port, protocol, 'client')
        self.p2s = ProxyWare(to_host, port, protocol, 'server')
        self.from_host = from_host
        self.app = Flask(__name__)
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

        @self.app.route('/', methods=['GET', 'POST'])
        @self.app.route('/<path:text>', methods=['GET', 'POST'])
        def all_routes(text=''):
            req_params = dict(request.args)
            req_headers = dict(request.headers)
            remote_hostname = to_host
            if from_host == to_host:
                remote_hostname = req_headers['Host']
            else:
                req_headers['Host'] = to_host
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
            self.app.run(host=self.from_host, port=self.port, ssl_context='adhoc')
        else:
            self.app.run(host=self.from_host, port=self.port)


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
    def __init__(self, from_host, to_host, port, protocol):
        threading.Thread.__init__(self)
        self.daemon = True
        ProxyWare.__init__(self, to_host, port, protocol, 'proxy')
        self.from_host = from_host
        self.to_host = to_host
        self.port = port
        self.protocol = protocol
        self.g2p = None
        self.p2s = None

    def setup(self):
        ProxyWare.setup(self)
        self.g2p = Game2Proxy(self.from_host, self.port, self.protocol)
        self.p2s = Proxy2Server(self.to_host, self.port, self.protocol)
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


def main(host=('127.0.0.1',), proxy=('127.0.0.1:8080',), dns=tuple()):
    """
    :param host: list of host (only first host will be used as of now)
    :param proxy: list of proxy server to create
    :param dns: list of custom dns server ['8.8.8.8']
    """
    dns = list(dns)
    init_dns_resolver(dns)
    for remote in proxy:
        protocol = remote.find('://')
        if protocol == -1:
            protocol = 'tcp'
        else:
            protocol = remote[:protocol]
            remote = remote[len(protocol) + 3:]
        s = remote.split(':')
        if protocol in ['tcp', 'udp']:
            t = ProxyTCPUDP(host[0], resolve_hostname(':'.join(s[:-1])), int(s[-1]), protocol)
        elif protocol in ['http', 'https']:
            t = ProxyHttp(host[0], resolve_hostname(':'.join(s[:-1])), int(s[-1]), protocol)
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
    main(**parse_config('config.ini'))
