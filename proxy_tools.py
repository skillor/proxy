def parse_http_headers(lines):
    headers = {}
    i = 0
    while True:
        if not lines[i].strip():
            i += 1
            break
        s = lines[i].strip().decode('utf-8').split(': ')
        headers[s[0]] = ': '.join(s[1:])
        i += 1
    return headers, lines[i:]


def parse_http_request(data):
    lines = data.splitlines(keepends=True)

    req = {}
    if not lines[0].split(b'/')[-1].endswith(b'HTTP'):
        t = lines[0].decode('utf-8').split(' ')
        if len(t) == 3:
            req['method'], req['path'], req['http_version'] = t
            req['headers'], lines = parse_http_headers(lines[1:])
    req['body'] = b''.join(lines)
    return req


def parse_http_response(data):
    res = {}
    lines = data.splitlines(keepends=True)
    if lines[0].startswith(b'HTTP'):
        t = lines[0].decode('utf-8').split(' ')
        if len(t) == 3:
            res['http_version'], res['status_code'], res['status'] = t
            res['headers'], lines = parse_http_headers(lines[1:])
    res['body'] = b''.join(lines)
    return res
