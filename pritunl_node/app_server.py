from constants import *
from server import Server
import tornado.ioloop
import tornado.web
import logging
import time

logger = logging.getLogger(APP_NAME)

class ServerHandler(tornado.web.RequestHandler):
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        network = data['network']
        local_networks = data['local_networks']
        ovpn_conf = data['ovpn_conf']

        server = Server(
            id=server_id,
            network=network,
            local_networks=local_networks,
            ovpn_conf=ovpn_conf,
        )
        server.initialize()
        server.start()

        self.write({
            'id': server.id,
        })

    def delete(self, server_id):
        server = Server(id=server_id)
        server.remove()

        self.write({
            'id': server_id,
        })

class ServerTlsVerifyHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']

        server = Server(id=server_id)
        call_buffer = server.call_buffer

        call_buffer.create_call('tls_verify', [org_id, user_id],
            self.on_response)

    def on_response(self, authenticated):
        self.finish({
            'authenticated': authenticated,
        })

class ServerOtpVerifyHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']
        otp_code = data['otp_code']

        server = Server(id=server_id)
        call_buffer = server.call_buffer

        call_buffer.create_call('otp_verify', [org_id, user_id, otp_code],
            self.on_response)

    def on_response(self, authenticated):
        self.finish({
            'authenticated': authenticated,
        })

class ServerComHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def put(self, server_id):
        server = Server(id=server_id)
        self.timeout = None
        self.call_buffer = server.call_buffer

        if not self.call_buffer:
            self.send_error(410)
            return

        for call in tornado.escape.json_decode(self.request.body):
            self.call_buffer.return_call(call['id'], call['response'])

        self.timeout = tornado.ioloop.IOLoop.current().add_timeout(
            time.time() + 30, self.on_new_calls)
        self.call_buffer.wait_for_calls(self.on_new_calls)

    def write(self, chunk):
        if isinstance(chunk, list):
            self.set_header('Content-Type', 'application/json; charset=UTF-8')
            chunk = tornado.escape.json_encode(chunk)
        super(ServerComHandler, self).write(chunk)

    def on_new_calls(self, calls=[]):
        if self.request.connection.stream.closed():
            return
        if calls is None:
            self.send_error(410)
        else:
            self.finish(calls)

    def on_finish(self):
        if self.call_buffer:
            self.call_buffer.cancel_waiter()
        if self.timeout:
            tornado.ioloop.IOLoop.current().remove_timeout(self.timeout)

application = tornado.web.Application([
    (r'/server/([a-z0-9]+)', ServerHandler),
    (r'/server/([a-z0-9]+)/com', ServerComHandler),
    (r'/server/([a-z0-9]+)/tls_verify', ServerTlsVerifyHandler),
    (r'/server/([a-z0-9]+)/otp_verify', ServerOtpVerifyHandler),
])

def run_server():
    try:
        application.listen(SERVER_PORT)
        tornado.ioloop.IOLoop.instance().start()
    finally:
        for server in Server.get_servers():
            server.remove()
