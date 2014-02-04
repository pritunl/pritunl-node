from constants import *
from config import Config
from server import Server
import tornado.ioloop
import tornado.web
import logging
import time
import functools
import subprocess
import os
import uuid

logger = logging.getLogger(APP_NAME)

class AppServer(Config):
    bool_options = {'ssl', 'log_debug'}
    int_options = {'port'}
    path_options = {'log_path', 'data_path', 'server_cert_path',
        'server_key_path'}
    str_options = {'bind_addr', 'api_key'}
    default_options = {
        'get_public_ip': True,
        'inline_certs': True,
        'ssl': True,
        'data_path': DEFAULT_DATA_PATH,
    }
    chmod_mode = 0600

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

    def _setup_conf(self):
        self.set_path(self.conf_path)
        if not os.path.isdir(self.data_path):
            os.makedirs(self.data_path)

        if not self.api_key:
            self.api_key = uuid.uuid4().hex
            self.commit()

    def _setup_log(self):
        if self.log_debug:
            self.log_level = logging.DEBUG
        else:
            self.log_level = logging.INFO

        if self.log_path:
            self.log_handler = logging.FileHandler(self.log_path)
        else:
            self.log_handler = logging.StreamHandler()

        logger.setLevel(self.log_level)
        self.log_handler.setLevel(self.log_level)

        self.log_handler.setFormatter(logging.Formatter(
            '[%(asctime)s][%(levelname)s][%(module)s][%(lineno)d] ' +
            '%(message)s'))

        logger.addHandler(self.log_handler)

    def _setup_handlers(self):
        import handlers

    def _setup_server_cert(self):
        if self.server_cert_path and self.server_key_path:
            self._server_cert_path = self.server_cert_path
            self._server_key_path = self.server_key_path
        else:
            self._server_cert_path = os.path.join(self.data_path,
                SERVER_CERT_NAME)
            self._server_key_path = os.path.join(self.data_path,
                SERVER_KEY_NAME)

            if not os.path.isfile(self._server_cert_path) or \
                    not os.path.isfile(self._server_key_path):
                logger.info('Generating server ssl cert...')
                try:
                    subprocess.check_call([
                        'openssl', 'req', '-batch', '-x509', '-nodes',
                        '-newkey', 'rsa:4096',
                        '-days', '3652',
                        '-keyout', self._server_key_path,
                        '-out', self._server_cert_path,
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except subprocess.CalledProcessError:
                    logger.exception('Failed to generate server ssl cert.')
                    raise
                os.chmod(self._server_key_path, 0600)

    def _setup_all(self):
        self._setup_app()
        self._setup_conf()
        self._setup_log()
        self._setup_handlers()

    def _run_server(self):
        if self.ssl:
            self._setup_server_cert()
        try:
            self.app.listen(SERVER_PORT, ssl_options={
                'certfile': self._server_cert_path,
                'keyfile': self._server_key_path,
            })
            tornado.ioloop.IOLoop.instance().start()
        finally:
            for server in Server.get_servers():
                server.remove()

    def run_server(self):
        self._setup_all()
        self._run_server()
