from constants import *
import collections
import uuid

class CallBuffer():
    def __init__(self):
        self.waiter = None
        self.queue = collections.deque(maxlen=CALL_QUEUE_MAX)
        self.call_waiters = {}

    def wait_for_calls(self, callback):
        self.stop_waiter()
        self.waiter = callback
        calls = []
        while True:
            try:
                calls.append(self.queue.popleft())
            except IndexError:
                break
        if calls:
            callback(calls)
            return

    def cancel_waiter(self):
        self.waiter = None

    def stop_waiter(self):
        if self.waiter:
            self.waiter(None)
            self.waiter = None

    def return_call(self, call_id, response):
        callback = self.call_waiters.pop(call_id, None)
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

        if self.waiter:
            self.waiter([call])
        else:
            self.queue.append(call)

        return call_id

    def cancel_call(self, call_id):
        self.call_waiters.pop(call_id, None)
