from constants import *
from call_buffer import CallBuffer
import subprocess
import os
import signal
import threading
import traceback
import logging
import time
import utils
import re

logger = logging.getLogger(APP_NAME)
_threads = {}
_events = {}
_process = {}
_call_buffers = {}

class Server:
    def __init__(self, id=None, network=None, local_networks=None,
             ovpn_conf=None):
        self.id = id
        self.network = network
        self.local_networks = local_networks
        self.ovpn_conf = ovpn_conf

        self.path = os.path.join(DATA_DIR, self.id)
        self.ovpn_conf_path = os.path.join(self.path, OVPN_CONF_NAME)
        self.ifc_pool_path = os.path.join(self.path, IFC_POOL_NAME)
        self.tls_verify_path = os.path.join(self.path, TLS_VERIFY_NAME)
        self.user_pass_verify_path = os.path.join(
            self.path, USER_PASS_VERIFY_NAME)
        self.ovpn_status_path = os.path.join(self.path, OVPN_STATUS_NAME)
        self.auth_log_path = os.path.join(DATA_DIR, AUTH_LOG_NAME)

    def __getattr__(self, name):
        if name == 'status':
            if self.id in _threads:
                return _threads[self.id].is_alive()
            return False
        elif name == 'call_buffer':
            try:
                return _call_buffers[self.id]
            except KeyError:
                return
        elif name not in self.__dict__:
            raise AttributeError('Server instance has no attribute %r' % name)
        return self.__dict__[name]

    def initialize(self):
        logger.info('Initialize server. %r' % {
            'server_id': self.id,
        })
        if self.status:
            self.remove()
        _call_buffers[self.id] = CallBuffer()
        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    def _parse_network(self, network):
        network_split = network.split('/')
        address = network_split[0]
        cidr = int(network_split[1])
        subnet = ('255.' * (cidr / 8)) + str(
            int(('1' * (cidr % 8)).ljust(8, '0'), 2))
        subnet += '.0' * (3 - subnet.count('.'))
        return (address, subnet)

    def _generate_ovpn_conf(self):
        self._generate_tls_verify()
        server_conf = self.ovpn_conf % (
            self.tls_verify_path,
            self.ifc_pool_path,
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
                self.auth_log_path,
                SERVER_PORT,
                self.id,
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

    def _generate_iptable_rules(self):
        iptable_rules = []

        try:
            routes_output = utils.check_output(['route', '-n'],
                stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logger.exception('Failed to get IP routes. %r' % {
                'server_id': self.id,
            })
            raise

        routes = {}
        for line in routes_output.splitlines():
            line_split = line.split()
            if len(line_split) < 8 or not re.match(IP_REGEX, line_split[0]):
                continue
            routes[line_split[0]] = line_split[7]

        if '0.0.0.0' not in routes:
            logger.error('Failed to find default network interface. %r' % {
                'server_id': self.id,
            })
            raise ValueError('Failed to find default network interface')
        default_interface = routes['0.0.0.0']

        for network_address in self.local_networks or ['0.0.0.0/0']:
            args = []
            network = self._parse_network(network_address)[0]

            if network not in routes:
                logger.debug('Failed to find interface for local network ' + \
                        'route, using default route. %r' % {
                    'server_id': self.id,
                })
                interface = default_interface
            else:
                interface = routes[network]

            if network != '0.0.0.0':
                args += ['-d', network_address]

            args += ['-s', self.network, '-o', interface, '-j', 'MASQUERADE']
            iptable_rules.append(args)

        return iptable_rules

    def _exists_iptable_rules(self):
        logger.debug('Checking for iptable rules. %r' % {
            'server_id': self.id,
        })
        for iptable_rule in self._generate_iptable_rules():
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
        for iptable_rule in self._generate_iptable_rules():
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

        for iptable_rule in self._generate_iptable_rules():
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
        _events.pop(self.id, None)

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
                self.call_buffer.create_call(
                    'push_output', [traceback.format_exc()])
                logger.exception('Failed to start ovpn process. %r' % {
                    'server_id': self.id,
                })
                return

            while True:
                line = process.stdout.readline()
                if line == '' and process.poll() is not None:
                    break
                if line:
                    self.call_buffer.create_call('push_output', [line])

            logger.debug('Ovpn process has ended. %r' % {
                'server_id': self.id,
            })
        finally:
            _threads.pop(self.id, None)
            _process.pop(self.id, None)
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
        logger.debug('Forcing stop server. %r' % {
            'server_id': self.id,
        })
        process = _process[self.id]
        event = _events[self.id]

        process.send_signal(signal.SIGINT)
        if not event.wait(2):
            process.send_signal(signal.SIGKILL)
            if not event.wait(THREAD_EVENT_TIMEOUT):
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

        utils.rmtree(self.path)
        call_buffer = _call_buffers.pop(self.id, None)
        if call_buffer:
            call_buffer.stop_waiter()
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
