from pritunl_node.constants import *
from pritunl_node.server import Server
from pritunl_node.auth_handler import AuthHandler, AuthLocalHandler
from pritunl_node import app_server
import tornado.ioloop
import tornado.web
import logging
import time

logger = logging.getLogger(APP_NAME)

class ServerHandler(AuthHandler):
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        network = data['network']
        local_networks = data['local_networks']
        ovpn_conf = data['ovpn_conf']
        server_ver = 0
        if 'server_ver' in data:
            server_ver = data['server_ver']

        server = Server(
            id=server_id,
            network=network,
            local_networks=local_networks,
            ovpn_conf=ovpn_conf,
            server_ver=server_ver,
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
app_server.app.add_handlers('.*', [(r'/server/([a-z0-9]+)', ServerHandler)])

class ServerTlsVerifyHandler(AuthLocalHandler):
    timeout = None
    call_id = None

    @tornado.web.asynchronous
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']
        server = Server(id=server_id)
        self.call_buffer = server.call_buffer

        self.timeout = tornado.ioloop.IOLoop.current().add_timeout(
            time.time() + CALL_RESPONSE_TIMEOUT, self.on_timeout)

        self.call_id = self.call_buffer.create_call('tls_verify',
            [org_id, user_id], self.on_response)

    def on_timeout(self):
        self.send_error(504)

    def on_response(self, authenticated):
        if self.request.connection.stream.closed():
            return
        self.finish({
            'authenticated': authenticated,
        })

    def on_finish(self):
        if self.call_id:
            self.call_buffer.cancel_call(self.call_id)
        if self.timeout:
            tornado.ioloop.IOLoop.current().remove_timeout(self.timeout)
app_server.app.add_handlers('.*', [(r'/server/([a-z0-9]+)/tls_verify',
    ServerTlsVerifyHandler)])

class ServerOtpVerifyHandler(AuthLocalHandler):
    timeout = None
    call_id = None

    @tornado.web.asynchronous
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']
        otp_code = data['otp_code']
        server = Server(id=server_id)
        self.call_buffer = server.call_buffer

        self.timeout = tornado.ioloop.IOLoop.current().add_timeout(
            time.time() + CALL_RESPONSE_TIMEOUT, self.on_timeout)

        self.call_id = self.call_buffer.create_call('otp_verify',
            [org_id, user_id, otp_code], self.on_response)

    def on_timeout(self):
        self.send_error(504)

    def on_response(self, authenticated):
        if self.request.connection.stream.closed():
            return
        self.finish({
            'authenticated': authenticated,
        })

    def on_finish(self):
        if self.call_id:
            self.call_buffer.cancel_call(self.call_id)
        if self.timeout:
            tornado.ioloop.IOLoop.current().remove_timeout(self.timeout)
app_server.app.add_handlers('.*', [(r'/server/([a-z0-9]+)/otp_verify',
    ServerOtpVerifyHandler)])

class ServerClientConnectHandler(AuthLocalHandler):
    timeout = None
    call_id = None

    @tornado.web.asynchronous
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']
        server = Server(id=server_id)
        self.call_buffer = server.call_buffer

        self.timeout = tornado.ioloop.IOLoop.current().add_timeout(
            time.time() + CALL_RESPONSE_TIMEOUT, self.on_timeout)

        self.call_id = self.call_buffer.create_call('client_connect',
            [org_id, user_id], self.on_response)

    def on_timeout(self):
        self.send_error(504)

    def on_response(self, client_conf):
        if self.request.connection.stream.closed():
            return
        self.finish({
            'client_conf': client_conf,
        })

    def on_finish(self):
        if self.call_id:
            self.call_buffer.cancel_call(self.call_id)
        if self.timeout:
            tornado.ioloop.IOLoop.current().remove_timeout(self.timeout)
app_server.app.add_handlers('.*', [(r'/server/([a-z0-9]+)/client_connect',
    ServerClientConnectHandler)])

class ServerClientDisconnectHandler(AuthLocalHandler):
    timeout = None
    call_id = None

    @tornado.web.asynchronous
    def post(self, server_id):
        data = tornado.escape.json_decode(self.request.body)
        org_id = data['org_id']
        user_id = data['user_id']
        server = Server(id=server_id)
        self.call_buffer = server.call_buffer

        self.timeout = tornado.ioloop.IOLoop.current().add_timeout(
            time.time() + CALL_RESPONSE_TIMEOUT, self.on_timeout)

        self.call_id = self.call_buffer.create_call('client_disconnect',
            [org_id, user_id], self.on_response)

    def on_timeout(self):
        self.send_error(504)

    def on_response(self, response):
        if self.request.connection.stream.closed():
            return
        self.finish({})

    def on_finish(self):
        if self.call_id:
            self.call_buffer.cancel_call(self.call_id)
        if self.timeout:
            tornado.ioloop.IOLoop.current().remove_timeout(self.timeout)
app_server.app.add_handlers('.*', [(r'/server/([a-z0-9]+)/client_disconnect',
    ServerClientDisconnectHandler)])

class ServerComHandler(AuthHandler):
    call_buffer = None
    timeout = None

    @tornado.web.asynchronous
    def put(self, server_id):
        server = Server(id=server_id)
        self.call_buffer = server.call_buffer

        if not self.call_buffer:
            self.send_error(410)
            return

        for call in tornado.escape.json_decode(self.request.body):
            self.call_buffer.return_call(call['id'], call['response'])

        self.timeout = tornado.ioloop.IOLoop.current().add_timeout(
            time.time() + 5, self.on_new_calls)
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
app_server.app.add_handlers('.*', [(r'/server/([a-z0-9]+)/com',
    ServerComHandler)])
