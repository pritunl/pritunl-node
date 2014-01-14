from constants import *
from pritunl_node import call_buffer
import tornado.ioloop
import tornado.web
import logging

logger = logging.getLogger(APP_NAME)

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
    (r'/com', ComHandler),
    (r'/com/([a-z0-9]+)', ComHandler),
])

def run_server():
    application.listen(SERVER_PORT)
    tornado.ioloop.IOLoop.instance().start()
