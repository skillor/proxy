def parse(data, proxy):
    print('{}[{}://{}:{}]{}'.format(proxy.origin, proxy.protocol, proxy.id, proxy.port, data))
    return data
