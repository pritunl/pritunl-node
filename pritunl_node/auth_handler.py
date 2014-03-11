from pritunl_node import app_server
import tornado.web
import tornado.websocket

class AuthHandler(tornado.web.RequestHandler):
    def prepare(self):
        if self.request.headers.get('API-Key') != app_server.api_key:
            raise tornado.web.HTTPError(401)

class AuthLocalHandler(tornado.web.RequestHandler):
    def prepare(self):
        if self.request.remote_ip not in ('127.0.0.1', '::1'):
            raise tornado.web.HTTPError(401)

class WebSocketAuthHandler(tornado.websocket.WebSocketHandler):
    def authenticate(self):
        return self.request.headers.get('API-Key') == app_server.api_key
