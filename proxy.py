import os

import socket
import threading
import ssl

from OpenSSL import crypto

try:
    from .tools.protocols import *
    from .tools.http import *
except ImportError:
    from tools.protocols import *
    from tools.http import *

RUNNING_I = 0


def get_id():
    global RUNNING_I
    RUNNING_I += 1
    return RUNNING_I - 1


class Cert:
    def __init__(self,
                 kwargs,
                 suffix,
                 ):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        cert = crypto.X509()

        cert.get_subject().C = get_kwarg(kwargs, 'cert_country'+suffix, 'US')
        cert.get_subject().ST = get_kwarg(kwargs, 'cert_state'+suffix, 'Nevada')
        cert.get_subject().L = get_kwarg(kwargs, 'cert_local'+suffix, 'us')
        cert.get_subject().O = get_kwarg(kwargs, 'cert_org'+suffix, 'proxy')
        cert.get_subject().OU = get_kwarg(kwargs, 'cert_org_unit'+suffix, 'proxy-team')
        cert.get_subject().CN = get_kwarg(kwargs, 'cert_common_name'+suffix, 'proxy')
        cert.get_subject().emailAddress = get_kwarg(kwargs, 'cert_email'+suffix, 'proxy@example.org')
        cert.set_serial_number(get_kwarg(kwargs, 'cert_serial_number'+suffix, 0))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(get_kwarg(kwargs, 'cert_validity_seconds'+suffix, 10 * 365 * 24 * 60 * 60))
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        self.private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8')
        self.public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, k).decode('utf-8')
        self.certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')


def load_ssl_context(kwargs, suffix):
    ssl_context = get_kwarg(kwargs, 'ssl_context'+suffix)
    if not issubclass(type(ssl_context), ssl.SSLContext):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        cert_bundle_file = get_kwarg(kwargs, 'cert_bundle'+suffix, 'cert.pem')
        try:
            ssl_context.load_cert_chain(certfile=cert_bundle_file, keyfile=cert_bundle_file)
        except (FileNotFoundError, ssl.SSLError):
            temp_cert = Cert(kwargs, suffix)
            with open(cert_bundle_file, 'w+') as f:
                before = f.read()
                f.write(before + temp_cert.private_key + temp_cert.certificate)
            ssl_context.load_cert_chain(certfile=cert_bundle_file, keyfile=cert_bundle_file)
            with open(cert_bundle_file, 'w') as f:
                f.write(before)
    return ssl_context


def get_kwarg(kwargs, key, default=None):
    if key in kwargs:
        return kwargs[key]
    return default


def ip_port_to_host(ip, port, protocol=None):
    host = ip
    if port >= 0:
        host = '{}:{}'.format(host, port)
    if protocol is not None:
        host = '{}://{}'.format(protocol, host)
    return host

def host_to_ip_port(h):
    protocol = h.find('://')
    if protocol == -1:
        protocol = 'tcp'
    else:
        protocol = h[:protocol]
        h = h[len(protocol) + 3:]
    s = h.split(':')
    port = -1
    if len(s) == 1:
        return h, port, protocol
    try:
        port = int(s[-1])
    except ValueError:
        pass
    return ':'.join(s[:-1]), port, protocol


def parse_config(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()
    i = 0
    d = {}
    for line in lines:
        if line == '' or line.startswith(';'):
            continue
        s = line.split('=')
        k, v = s[0].lower(), '='.join(s[1:])
        for k2 in d.keys():
            if k2 != k:
                d[k2].append(None)
        if k not in d:
            d[k] = [None] * i
        d[k].append(v)
        i += 1
    return d


class ProxyWare:
    def __init__(self, handler, address, protocol, origin, kwargs):
        self.handler = handler
        self.id = get_id()
        self.running = False
        self.address = address
        self.host = address[0]
        self.port = address[1]
        self.address_str = '{}:{}'.format(self.host, self.port)
        self.protocol = protocol
        self.origin = origin
        self.kwargs = kwargs
        self.logging = not ('logging' in kwargs and kwargs['logging'] == '0')

    def listening(self):
        self.log('listening')

    def connection_established(self):
        self.log('connection established')

    def closed_connection(self):
        self.log('closed connection')
    
    def lost_connection(self):
        self.log('lost connection')

    def log(self, msg):
        if self.logging:
            print('{}[{}://{}:{}]{}'.format(self.origin, self.protocol, self.id, self.port, msg))


class ProxyServer(ProxyWare, threading.Thread):
    def __init__(self, handler, protocol, from_addr, to_addr, kwargs):
        threading.Thread.__init__(self, daemon=True)
        ProxyWare.__init__(self, handler, from_addr, protocol, 'proxy', kwargs)
        self.to_addr = to_addr
        if self.protocol == 'udp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(from_addr)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.protocol in CLIENT_SSL_PROTOCOLS:
                self.ssl_context = load_ssl_context(kwargs, '')
                self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=True)
            self.socket.bind(from_addr)
            self.socket.listen()
            self.socket.settimeout(get_kwarg(self.kwargs, 'server_socket_timeout', 1))

    def run(self):
        self.running = True
        self.listening()
        if self.protocol == 'udp':
            Client(self.handler, self.protocol, 'client', self.kwargs, self.socket, None, self.to_addr).start()
        else:
            while True:
                try:
                    conn, _ = self.socket.accept()
                    self.connection_established()
                    Client(self.handler, self.protocol, 'client', self.kwargs, conn, None, (
                        None if self.to_addr[0] == self.address[0] else self.to_addr[0],
                        None if self.to_addr[1] < 0 else self.to_addr[1]),
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log('[ERROR]{}'.format(e))



class Client(ProxyWare, threading.Thread):
    def __init__(self, handler, protocol, origin, kwargs, listener, sender, address, partner = None):
        threading.Thread.__init__(self, daemon=True)
        ProxyWare.__init__(self, handler, address, protocol, origin, kwargs)
        self.listener = listener
        self.sender = sender
        self.partner = partner
        self.content_buffer = 0

    def close(self):
        if not self.running:
            return
        self.running = False
        if self.listener is not None:
            self.listener.shutdown(socket.SHUT_RDWR)
            self.listener.close()
            self.listener = None
        self.closed_connection()
        if self.partner is not None:
            self.partner.close()

    def run(self):
        self.running = True
        if self.protocol == 'udp':
            server = ProxyWare(self.handler, self.address, self.protocol, 'server', self.kwargs)
            client_address = None
            self.listener.settimeout(get_kwarg(self.kwargs, 'client_socket_timeout', 1))
            while self.running:
                try:
                    data, address = self.listener.recvfrom(get_kwarg(self.kwargs, 'buffer_size', 4096))
                except socket.timeout:
                    continue
                if client_address is None:
                    client_address = address
                if address == self.address:
                    data, status = self.handler.parse(data, server)
                    if status == 2:
                        self.listener.sendto(data, address)
                    elif status == 1:
                        self.listener.sendto(data, client_address)
                        client_address = None
                else:
                    data, status = self.handler.parse(data, self)
                    if status == 2:
                        self.listener.sendto(data, address)
                    elif status == 1:
                        client_address = address
                        if self.sender is None:
                            self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            self.sender.bind(('0.0.0.0', self.address[1]))
                            Client(self.handler, self.protocol, 'server', self.kwargs,
                                   self.sender, self.listener, address).start()
                        self.sender.sendto(data, self.address)
        else:
            self.listener.settimeout(1)
            while self.running:
                try:
                    data = self.listener.recv(get_kwarg(self.kwargs, 'buffer_size',  1024 * 1024))
                except socket.timeout:
                    continue
                except ConnectionAbortedError:
                    self.lost_connection()
                    break
                except OSError:
                    break
                data, status = self.handler.parse(data, self)
                if status == 2:
                    self.listener.sendall(data)
                    if self.protocol in HTTP_PROTOCOLS and self.origin == 'client':
                        self.close()
                        break
                elif status == 1:
                    if self.origin == 'server':
                        if self.protocol in HTTP_PROTOCOLS:
                            try:
                                parsed = parse_http_response(data)
                                parsed['headers']['access-control-allow-origin'] = '*'
                                if 'x-frame-options' in parsed['headers']:
                                    del parsed['headers']['x-frame-options']
                                data = serialize_http_response(parsed)
                                if self.content_buffer >= 0 and 'content-length' in parsed['headers']:
                                    self.content_buffer += int(parsed['headers']['content-length']) - len(parsed['body'])
                                if 'transfer-encoding' in parsed['headers'] and parsed['headers']['transfer-encoding'] == 'chunked':
                                    self.content_buffer = -1
                            except Exception as e:
                                self.log('[ERROR]{}@{}'.format(e, data))
                                if self.content_buffer >= 0:
                                    self.content_buffer -= len(data)
                            if self.content_buffer == 0 or (self.content_buffer == -1 and data.endswith(b'0\r\n\r\n')):
                                self.sender.sendall(data)
                                self.close()
                                break
                    else:
                        if self.protocol in HTTP_PROTOCOLS:
                            try:
                                parsed = parse_http_request(data)
                                if (parsed['method'] == 'OPTIONS'
                                    and 'access-control-request-headers' in parsed['headers']
                                    and 'x-proxy-prevent-options' in parsed['headers']['access-control-request-headers'].split(',')):
                                    self.listener.sendall(serialize_http_response({
                                        'http_version': 'HTTP/1.1',
                                        'status_code': '204',
                                        'status': 'No Content',
                                        'headers': {
                                            'access-control-allow-origin': '*',
                                            'access-control-allow-credentials': 'true',
                                            'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
                                            'access-control-allow-headers': parsed['headers']['access-control-request-headers']
                                        },
                                        'body': b'',
                                    }))
                                    self.close()
                                    break
                            except Exception as e:
                                self.log('[ERROR]{}@{}'.format(e, data))

                    if self.sender is None:
                        addr = list(self.address)
                        if self.protocol in HTTP_PROTOCOLS: 
                            try:
                                parsed = parse_http_request(data)
                                host, port = None, -1
                                if 'x-proxy-host' in parsed['headers']:
                                    host, port, _ = host_to_ip_port(parsed['headers']['x-proxy-host'])
                                    if addr[0] is None and host is not None:
                                        addr[0] = self.handler.resolve_hostname(host)
                                        parsed['headers']['host'] = ip_port_to_host(host, port)
                                        data = serialize_http_request(parsed)
                                    if port >= 0:
                                        addr[1] = port
                                elif addr[0] is not None:
                                    parsed['headers']['host'] = ip_port_to_host(addr[0], addr[1])
                                    data = serialize_http_request(parsed)
                            except Exception as e:
                                self.log('[ERROR]{}@{}'.format(e, data))


                        addr = tuple(addr)
                        if addr[0] is not None and addr[1] is not None:
                            self.sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            if self.protocol in SERVER_SSL_PROTOCOLS:
                                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                self.sender = context.wrap_socket(self.sender,
                                                                  server_hostname=addr[0],
                                                                  do_handshake_on_connect=True)
                            self.sender.connect(addr)
                            self.partner = Client(self.handler, self.protocol, 'server', self.kwargs,
                                                  self.sender, self.listener, addr, self)
                            self.partner.start()
                        

                    if self.sender is not None and self.running:
                        try:
                            self.sender.sendall(data)
                        except Exception as e:
                            self.log('[ERROR]{}@{}'.format(e, data))


class ProxyHandler(threading.Thread):
    def __init__(self, parse, **kwargs):
        """
        :param parse: function to parse the data parse(data, proxy: ProxyWare)
        :param host: list of hosts
        :param proxy: list of proxy server to create
        :param dns: list of custom dns server ['8.8.8.8']
        """
        threading.Thread.__init__(self, daemon=True)
        self.parse = parse
        self.kwargs = kwargs
        self.dns = [s for s in get_kwarg(kwargs, 'dns', []) if s is not None]
        self.dns_cache = {}
        self.dns_resolver = None

    def resolve_hostname(self, hostname):
        if self.dns_resolver is None:
            return hostname

        if hostname in self.dns_cache:
            return self.dns_cache[hostname]

        import dns.resolver
        try:
            _t = self.dns_resolver.resolve(hostname, 'A')[0].to_text()
        except dns.resolver.NXDOMAIN:
            _t = hostname
        self.dns_cache[hostname] = _t
        return _t

    def get_kwargs(self, ci):
        d = {}
        for key in self.kwargs.keys():
            kwarg = self.kwargs[key]
            i = ci
            while i >= 0:
                if kwarg[i] is not None:
                    d[key] = kwarg[i]
                    break
                i -= 1
        return d

    def run(self):
        if len(self.dns) == 0:
            pass
        else:
            import dns.resolver
            self.dns_resolver = dns.resolver.Resolver(configure=False)
            self.dns_resolver.nameservers = self.dns

        ignore_duplicates = set()
        for i, remote in enumerate(self.kwargs['proxy']):
            if remote is None:
                continue
            kwargs = self.get_kwargs(i)
            local_host, local_port, _ = host_to_ip_port(kwargs['host'])
            remote_host, remote_port, protocol = host_to_ip_port(remote)
            addresses = (local_host, local_port), (self.resolve_hostname(remote_host), remote_port), protocol
            if addresses in ignore_duplicates:
                continue
            ignore_duplicates.add(addresses)
            if protocol in PROTOCOLS:
                t = ProxyServer(self,
                                protocol,
                                addresses[0],
                                addresses[1],
                                kwargs,
                                )
            else:
                raise Exception('unknown protocol: ' + protocol)
            t.start()

        while True:
            cmd = input('$ ')
            if cmd == '':
                continue
            elif cmd in ['q', 'quit']:
                exit(0)
            elif cmd in ['cls', 'clear']:
                os.system('cls' if os.name=='nt' else 'clear')
            else:
                print('Unknown command "{}"'.format(cmd))


def start_proxy(*args, **kwargs):
    p = ProxyHandler(*args, **kwargs)
    p.run()
    return p


def main():
    try:
        from importlib import reload
        import parse as parser
    except ModuleNotFoundError:
        cwd = os.path.dirname(os.path.realpath(__file__))
        parse_path = os.path.join(cwd, 'parse.py')
        config_path = os.path.join(cwd, 'config.ini')
        if not os.path.exists(parse_path):
            print('creating', parse_path)
            with open(parse_path, 'w', encoding='utf-8') as f:
                f.write('''def parse(data, proxy):
    if not data:
        return data, 0
    proxy.log(data)
    return data, 1 # status 0 for blocking, 1 for forward, 2 for return
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

    def _parse(data, proxy):
        try:
            reload(parser)
            return parser.parse(data, proxy)
        except Exception as e:
            proxy.log('[ERROR]{}@{}'.format(e, data))
        return data, 1

    cwd = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(cwd, 'config.ini')
    start_proxy(_parse, **parse_config(config_path))


if __name__ == '__main__':
    main()
