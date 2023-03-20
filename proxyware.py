import proxy_parser as parser
from importlib import reload

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
