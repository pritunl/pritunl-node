from constants import *
from config import Config
from server import Server
import tornado.ioloop
import tornado.web
import logging
import time
import functools

logger = logging.getLogger(APP_NAME)

class AppServer(Config):
    bool_options = {'ssl'}
    int_options = {'port'}
    path_options = {'data_path'}
    str_options = {'bind_addr', 'api_key'}
    default_options = {
        'get_public_ip': True,
        'inline_certs': True,
        'ssl': False,
        'data_path': DEFAULT_DATA_PATH,
    }

    def __init__(self):
        Config.__init__(self)
        self.app = tornado.web.Application()

    def __getattr__(self, name):
        if name == 'web_protocol':
            if self.ssl:
                return 'http'
            return 'https'
        return Config.__getattr__(self, name)

    def auth(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            if self.request.headers.get('API-Key') != self.api_key:
                raise tornado.web.HTTPError(401)
            return method(self, *args, **kwargs)
        return wrapper

    def _setup_app(self):
        self.app = tornado.web.Application()

    def _setup_handlers(self):
        import handlers

    def _setup_all(self):
        self._setup_app()
        self._setup_handlers()

    def _run_server(self):
        try:
            self.app.listen(SERVER_PORT)
            tornado.ioloop.IOLoop.instance().start()
        finally:
            for server in Server.get_servers():
                server.remove()

    def run_server(self):
        self._setup_all()
        self._run_server()
