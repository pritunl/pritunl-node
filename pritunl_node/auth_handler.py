from pritunl_node import app_server
import tornado.web

class AuthHandler(tornado.web.RequestHandler):
    def prepare(self):
        if self.request.headers.get('API-Key') != app_server.api_key:
            raise tornado.web.HTTPError(401)
