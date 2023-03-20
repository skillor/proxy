import socket
import threading
from proxyware import ProxyWare, parse


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
            self.client_address = None
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.address)
            self.socket.listen(1)

            self.conn, addr = self.socket.accept()

    def run(self):
        if self.protocol == 'udp':
            while True:
                data, address = self.socket.recvfrom(4096)
                if self.client_address is None:
                    self.client_address = address
                if address == self.client_address:
                    data = parse(data, self)
                    self.socket.sendto(data, self.server.address)
                elif address == self.server.address:
                    data = parse(data, self.server)
                    self.socket.sendto(data, self.client_address)
                    self.client_address = None
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
        ProxyTCPUDP.setup(self)
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
