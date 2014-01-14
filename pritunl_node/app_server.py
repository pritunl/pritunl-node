from constants import *
from server import Server
from pritunl_node import call_buffer
import tornado.ioloop
import tornado.web
import logging

logger = logging.getLogger(APP_NAME)

class ServerHandler(tornado.web.RequestHandler):
    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        iptable_rules = data['iptable_rules']
        ovpn_conf = data['ovpn_conf']

        server = Server(
            iptable_rules=iptable_rules,
            ovpn_conf=ovpn_conf,
        )
        server.start()

        self.write({
            'id': server.id,
        })

    def delete(self, server_id):
        server = Server(id=server_id)
        server.stop()

        self.write({
            'id': server_id,
        })

class TlsVerifyHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']

        call_buffer.create_call('tls_verify', [org_id, user_id],
            self.on_response)

    def on_response(self, authenticated):
        self.finish({
            'authenticated': authenticated,
        })

class OtpVerifyHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']
        otp_code = data['otp_code']

        call_buffer.create_call('otp_verify', [org_id, user_id, otp_code],
            self.on_response)

    def on_response(self, authenticated):
        self.finish({
            'authenticated': authenticated,
        })

class ComHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def put(self, cursor=None):
        for call in tornado.escape.json_decode(self.request.body):
            call_buffer.return_call(call['id'], call['response'])
        call_buffer.wait_for_calls(self.on_new_calls, cursor)

    def on_new_calls(self, calls):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.finish(tornado.escape.json_encode(calls))

application = tornado.web.Application([
    (r'/server', ServerHandler),
    (r'/server/([a-z0-9]+)', ServerHandler),
    (r'/com', ComHandler),
    (r'/com/([a-z0-9]+)', ComHandler),
    (r'/tls_verify', TlsVerifyHandler),
    (r'/otp_verify', OtpVerifyHandler),
])

def run_server():
    try:
        application.listen(SERVER_PORT)
        tornado.ioloop.IOLoop.instance().start()
    finally:
        for server in Server.get_servers():
            server.remove()
