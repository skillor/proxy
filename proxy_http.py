import threading

import requests
from flask import Flask, request, make_response
import logging
import urllib3.exceptions
import os

from proxyware import ProxyWare, parse

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
