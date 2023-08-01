from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

def parse_http_headers(lines):
    headers = {}
    i = 0
    while True:
        if not lines[i]:
            i += 1
            break
        s = lines[i].decode('utf-8').split(': ')
        headers[s[0].lower()] = ': '.join(s[1:])
        i += 1
    return headers, lines[i:]


def serialize_http_headers(headers):
    return b'\r\n'.join(['{}: {}'.format(k, v).encode('utf-8') for k, v in headers.items()])


def parse_http_request(data):
    lines = data.split(b'\r\n')
    req = {}
    t = lines[0].split(b' ')
    if len(t) == 3 and t[2].startswith(b'HTTP/'):
        req['method'], u, req['http_version'] = [x.decode('utf-8') for x in t]
        u = urlparse(u)
        req['url'] = u
        req['path'] = u.path
        req['query'] = {k: v[0] for k,v in parse_qs(u.query).items()}
        req['headers'], lines = parse_http_headers(lines[1:])
    req['body'] = b'\r\n'.join(lines)
    return req


def serialize_http_request(req):
    lines = []
    try:
        u = list(req['url'])
        u[2] = req['path']
        u[4] = urlencode(req['query'])
        lines.append(' '.join((req['method'], urlunparse(u), req['http_version'],)).encode('utf-8'))
        lines.append(serialize_http_headers(req['headers']))
        lines.append(b'')
    except KeyError:
        pass
    lines.append(req['body'])
    return b'\r\n'.join(lines)


def parse_http_response(data):
    res = {}
    lines = data.split(b'\r\n')
    if lines[0].startswith(b'HTTP/'):
        t = lines[0].decode('utf-8').split(' ')
        if len(t) >= 3:
            res['http_version'], res['status_code'], res['status'] = t[0], t[1], ' '.join(t[2:])
            res['headers'], lines = parse_http_headers(lines[1:])
    res['body'] = b'\r\n'.join(lines)
    return res


def serialize_http_response(res):
    lines = []
    try:
        lines.append(' '.join((res['http_version'], str(res['status_code']), res['status'],)).encode('utf-8'))
        lines.append(serialize_http_headers(res['headers']))
        lines.append(b'')
    except KeyError:
        pass
    lines.append(res['body'])
    return b'\r\n'.join(lines)
