from constants import *
from pritunl_node import call_buffer
import subprocess
import os
import signal
import threading
import traceback
import logging
import uuid
import time
import utils

logger = logging.getLogger(APP_NAME)
_threads = {}
_events = {}
_output = {}
_process = {}
_start_time = {}

class Server:
    def __init__(self, id=None, iptable_rules=None, ovpn_conf=None):
        if id is None:
            self._initialized = False
            self.id = uuid.uuid4().hex
        else:
            self._initialized = True
            self.id = id

        self.ovpn_conf = ovpn_conf
        self.iptable_rules = iptable_rules
        self.path = os.path.join(DATA_DIR, self.id)
        self.ovpn_conf_path = os.path.join(self.path, OVPN_CONF_NAME)
        self.tls_verify_path = os.path.join(self.path, TLS_VERIFY_NAME)
        self.user_pass_verify_path = os.path.join(
            self.path, USER_PASS_VERIFY_NAME)
        self.ovpn_status_path = os.path.join(self.path, OVPN_STATUS_NAME)
        self.auth_log_path = os.path.join(DATA_DIR, AUTH_LOG_NAME)

        if not self._initialized:
            self._initialize()

    def __getattr__(self, name):
        if name == 'status':
            if self.id in _threads:
                return _threads[self.id].is_alive()
            return False
        elif name == 'uptime':
            if self.status and self.id in _start_time:
                return int(time.time()) - _start_time[self.id]
            return None
        elif name not in self.__dict__:
            raise AttributeError('Server instance has no attribute %r' % name)
        return self.__dict__[name]

    def _initialize(self):
        logger.info('Initialize new server. %r' % {
            'server_id': self.id,
        })
        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    def _generate_ovpn_conf(self):
        self._generate_tls_verify()
        server_conf = self.ovpn_conf % (
            self.tls_verify_path,
            self.ovpn_status_path,
        )
        with open(self.ovpn_conf_path, 'w') as ovpn_conf:
            os.chmod(self.ovpn_conf_path, 0600)
            ovpn_conf.write(server_conf)

    def _generate_tls_verify(self):
        logger.debug('Generating tls verify script. %r' % {
            'server_id': self.id,
        })
        with open(self.tls_verify_path, 'w') as tls_verify_file:
            os.chmod(self.tls_verify_path, 0755)
            tls_verify_file.write(TLS_VERIFY_SCRIPT % (
                SERVER_PORT,
                self.auth_log_path,
            ))

    def _enable_ip_forwarding(self):
        try:
            subprocess.check_call(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logger.exception('Failed to enable IP forwarding. %r' % {
                'server_id': self.id,
            })
            raise

    def _exists_iptable_rules(self):
        logger.debug('Checking for iptable rules. %r' % {
            'server_id': self.id,
        })
        for iptable_rule in self.iptable_rules:
            try:
                subprocess.check_call(['iptables', '-t', 'nat', '-C',
                    'POSTROUTING'] + iptable_rule,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                return False
        return True

    def _set_iptable_rules(self):
        if self._exists_iptable_rules():
            return

        logger.debug('Setting iptable rules. %r' % {
            'server_id': self.id,
        })
        for iptable_rule in self.iptable_rules:
            try:
                subprocess.check_call(['iptables', '-t', 'nat', '-A',
                    'POSTROUTING'] + iptable_rule,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                logger.exception('Failed to apply iptables ' + \
                    'routing rules. %r' % {
                        'server_id': self.id,
                    })
                raise

    def _clear_iptable_rules(self):
        if not self._exists_iptable_rules():
            return
        logger.debug('Clearing iptable rules. %r' % {
            'server_id': self.id,
        })

        for iptable_rule in self.iptable_rules:
            try:
                subprocess.check_call(['iptables', '-t', 'nat', '-D',
                    'POSTROUTING'] + iptable_rule,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                logger.exception('Failed to clear iptables ' + \
                    'routing rules. %r' % {
                        'server_id': self.id,
                    })
                raise

    def get_clients(self):
        if not self.status:
            return []
        clients = {}

        if os.path.isfile(self.ovpn_status_path):
            with open(self.ovpn_status_path, 'r') as status_file:
                for line in status_file.readlines():
                    if line[:11] != 'CLIENT_LIST':
                        continue
                    line_split = line.strip('\n').split(',')
                    client_id = line_split[1]
                    real_address = line_split[2]
                    virt_address = line_split[3]
                    bytes_received = line_split[4]
                    bytes_sent = line_split[5]
                    connected_since = line_split[7]
                    clients[client_id] = {
                        'real_address': real_address,
                        'virt_address': virt_address,
                        'bytes_received': bytes_received,
                        'bytes_sent': bytes_sent,
                        'connected_since': connected_since,
                    }

        return clients

    def _status_thread(self):
        i = 0
        cur_client_count = 0
        while not self._interrupt:
            # Check interrupt every 0.1s check client count every 1s
            if i == 9:
                i = 0
                client_count = len(self.get_clients())
                if client_count != cur_client_count:
                    cur_client_count = client_count
                    # Event(type=USERS_UPDATED)
                    # Event(type=SERVERS_UPDATED)
            else:
                i += 1
            time.sleep(0.1)
        self._clear_iptable_rules()
        _events[self.id].set()
        try:
            del _events[self.id]
        except KeyError:
            pass

    def _run(self):
        logger.debug('Starting ovpn process. %r' % {
            'server_id': self.id,
        })
        self._interrupt = False
        try:
            threading.Thread(target=self._status_thread).start()

            try:
                process = subprocess.Popen(['openvpn', self.ovpn_conf_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                _process[self.id] = process
                _events[self.id].set()
            except OSError:
                _output[self.id] += traceback.format_exc()
                # self._event_delay(type=SERVER_OUTPUT_UPDATED,
                #     resource_id=self.id)
                logger.exception('Failed to start ovpn process. %r' % {
                    'server_id': self.id,
                })
                return

            while True:
                line = process.stdout.readline()
                if line == '' and process.poll() is not None:
                    break
                _output[self.id] += line
                if line:
                    print line.strip('\n')
                # self._event_delay(type=SERVER_OUTPUT_UPDATED,
                #     resource_id=self.id)

            logger.debug('Ovpn process has ended. %r' % {
                'server_id': self.id,
            })
        finally:
            try:
                del _threads[self.id]
            except KeyError:
                pass
            try:
                del _process[self.id]
            except KeyError:
                pass
            try:
                del _start_time[self.id]
            except KeyError:
                pass
            self._interrupt = True

    def start(self, silent=False):
        if self.status:
            return
        logger.debug('Starting server. %r' % {
            'server_id': self.id,
        })
        self._generate_ovpn_conf()
        self._enable_ip_forwarding()
        self._set_iptable_rules()
        _events[self.id] = threading.Event()
        thread = threading.Thread(target=self._run)
        thread.start()
        _threads[self.id] = thread
        _start_time[self.id] = int(time.time()) - 1
        _output[self.id] = ''
        if not _events[self.id].wait(THREAD_EVENT_TIMEOUT):
            raise ValueError('Server thread failed to return start event.')
        try:
            _events[self.id].clear()
        except KeyError:
            pass
        # if not silent:
        #     Event(type=SERVERS_UPDATED)
        #     LogEntry(message='Started server "%s".' % self.name)

    def stop(self, silent=False):
        if not self.status:
            return
        logger.debug('Stopping server. %r' % {
            'server_id': self.id,
        })
        _process[self.id].send_signal(signal.SIGINT)
        if not _events[self.id].wait(THREAD_EVENT_TIMEOUT):
            raise ValueError('Server thread failed to return stop event.')
        # if not silent:
        #     Event(type=SERVERS_UPDATED)
        #     LogEntry(message='Stopped server "%s".' % self.name)

    def force_stop(self, silent=False):
        if not self.status:
            return
        logger.info('Forcing stop server. %r' % {
            'server_id': self.id,
        })
        _process[self.id].send_signal(signal.SIGKILL)
        if not _events[self.id].wait(THREAD_EVENT_TIMEOUT):
            raise ValueError('Server thread failed to return stop event.')
        # if not silent:
        #     Event(type=SERVERS_UPDATED)
        #     LogEntry(message='Stopped server "%s".' % self.name)

    def remove(self):
        logger.info('Removing server. %r' % {
            'server_id': self.id,
        })

        if self.status:
            self.force_stop()
            for i in xrange(20):
                if not self.status:
                    break
                time.sleep(0.1)
            if self.status:
                self.force_stop()
                time.sleep(0.5)

        utils.rmtree(self.path)
        # LogEntry(message='Deleted server "%s".' % name)
        # Event(type=SERVERS_UPDATED)

    @staticmethod
    def get_servers():
        logger.debug('Getting servers.')
        path = os.path.join(DATA_DIR)
        servers = []
        if os.path.isdir(path):
            for server_id in os.listdir(path):
                servers.append(Server(server_id))
        return servers

    @staticmethod
    def has_server(server_id):
        path = os.path.join(DATA_DIR)
        if os.path.isdir(path) and server_id in os.listdir(path):
            return True
        return False
