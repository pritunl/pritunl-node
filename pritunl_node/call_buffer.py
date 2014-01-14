from constants import *
import collections
import uuid

class CallBuffer():
    def __init__(self):
        self.waiter = None
        self.cache = collections.deque(maxlen=CALL_CACHE_MAX)
        self.call_waiters = {}

    def wait_for_calls(self, callback, cursor=None):
        if self.waiter:
            self.waiter([])
            self.waiter = None
        calls = []
        cursor_found = False if cursor else True
        for call in self.cache:
            if call['id'] == cursor:
                cursor_found = True
                continue
            if not cursor_found:
                continue
            calls.append(call)
        if calls:
            callback(calls)
            return
        self.waiter = callback

    def return_call(self, id, response):
        callback = self.call_waiters.pop(id, None)
        if callback:
            callback(response)

    def create_call(self, command, args, callback=None):
        call_id = uuid.uuid4().hex
        call = {
            'id': call_id,
            'command': command,
            'args': args,
        }

        if callback:
            self.call_waiters[call_id] = callback
        self.cache.append(call)

        if self.waiter:
            self.waiter([call])
            self.waiter = None
