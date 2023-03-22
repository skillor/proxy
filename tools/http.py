def parse_http_headers(lines):
    headers = {}
    i = 0
    while True:
        if not lines[i]:
            i += 1
            break
        s = lines[i].decode('utf-8').split(': ')
        headers[s[0]] = ': '.join(s[1:])
        i += 1
    return headers, lines[i:]


def serialize_http_headers(headers):
    return b'\r\n'.join(['{}: {}'.format(k, v).encode('utf-8') for k, v in headers.items()])


def parse_http_request(data):
    lines = data.splitlines()

    req = {}
    if not lines[0].split(b'/')[-1].endswith(b'HTTP'):
        t = lines[0].decode('utf-8').split(' ')
        if len(t) == 3:
            req['method'], req['path'], req['http_version'] = t
            req['headers'], lines = parse_http_headers(lines[1:])
    req['body'] = b'\r\n'.join(lines)
    return req


def serialize_http_request(req):
    lines = []
    lines.append(' '.join((req['method'], req['path'], req['http_version'],)).encode('utf-8'))
    lines.append(serialize_http_headers(req['headers']))
    lines.append(req['body'])
    return b'\r\n'.join(lines)


def parse_http_response(data):
    res = {}
    lines = data.splitlines()
    if lines[0].startswith(b'HTTP/'):
        t = lines[0].decode('utf-8').split(' ')
        if len(t) == 3:
            res['http_version'], res['status_code'], res['status'] = t
            res['headers'], lines = parse_http_headers(lines[1:])
    res['body'] = b'\r\n'.join(lines)
    return res
