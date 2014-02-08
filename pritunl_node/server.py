from constants import *
from call_buffer import CallBuffer
from cache import cache_db
from pritunl_node import app_server
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
_call_buffers = {}

class Server:
    def __init__(self, id=None, network=None, local_networks=None,
             ovpn_conf=None, server_ver=None):
        self._cur_client_count = 0

        self.id = id
        self.network = network
        self.local_networks = local_networks
        self.ovpn_conf = ovpn_conf
        self.server_ver = server_ver

        self.path = os.path.join(app_server.data_path, self.id)
        self.ovpn_conf_path = os.path.join(self.path, OVPN_CONF_NAME)
        self.ifc_pool_path = os.path.join(self.path, IFC_POOL_NAME)
        self.tls_verify_path = os.path.join(self.path, TLS_VERIFY_NAME)
        self.user_pass_verify_path = os.path.join(
            self.path, USER_PASS_VERIFY_NAME)
        self.client_connect_path = os.path.join(self.path, CLIENT_CONNECT_NAME)
        self.client_disconnect_path = os.path.join(self.path,
            CLIENT_DISCONNECT_NAME)
        self.ovpn_status_path = os.path.join(self.path, OVPN_STATUS_NAME)
        self.auth_log_path = os.path.join(app_server.data_path, AUTH_LOG_NAME)

    def __setattr__(self, name, value):
        if name == 'status':
            if value:
                cache_db.dict_set(self.get_cache_key(), name, 't')
            else:
                cache_db.dict_set(self.get_cache_key(), name, 'f')
        else:
            self.__dict__[name] = value

    def __getattr__(self, name):
        if name == 'status':
            if cache_db.dict_get(self.get_cache_key(), name) == 't':
                return True
            return False
        elif name == 'call_buffer':
            return _call_buffers.get(self.id)
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

    def get_cache_key(self, suffix=None):
        key = 'server-%s' % self.id
        if suffix:
            key += '-%s' % suffix
        return key

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

    def _parse_network(self, network):
        network_split = network.split('/')
        address = network_split[0]
        cidr = int(network_split[1])
        subnet = ('255.' * (cidr / 8)) + str(
            int(('1' * (cidr % 8)).ljust(8, '0'), 2))
        subnet += '.0' * (3 - subnet.count('.'))
        return (address, subnet)

    def _generate_scripts(self):
        logger.debug('Generating openvpn scripts. %r' % {
            'server_id': self.id,
        })
        for script, script_path in (
                    (TLS_VERIFY_SCRIPT, self.tls_verify_path),
                    (USER_PASS_VERIFY_SCRIPT, self.user_pass_verify_path),
                    (CLIENT_CONNECT_SCRIPT, self.client_connect_path),
                    (CLIENT_DISCONNECT_SCRIPT, self.client_disconnect_path),
                ):
            with open(script_path, 'w') as script_file:
                os.chmod(script_path, 0755)
                script_file.write(script % (
                    self.auth_log_path,
                    app_server.web_protocol,
                    app_server.port,
                    self.id,
                ))

    def _generate_ovpn_conf(self):
        ovpn_conf = self.ovpn_conf
        self._generate_scripts()

        if '<%= user_pass_verify_path %>' in ovpn_conf:
            ovpn_conf = ovpn_conf.replace('<%= user_pass_verify_path %>',
                self.user_pass_verify_path)

        if self.server_ver == 0:
            server_conf = ovpn_conf % (
                self.tls_verify_path,
                self.ifc_pool_path,
                self.ovpn_status_path,
            )
        else:
            server_conf = ovpn_conf % (
                self.tls_verify_path,
                self.client_connect_path,
                self.client_disconnect_path,
                self.ifc_pool_path,
                self.ovpn_status_path,
            )

        with open(self.ovpn_conf_path, 'w') as ovpn_conf:
            os.chmod(self.ovpn_conf_path, 0600)
            ovpn_conf.write(server_conf)

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

    def _sub_thread(self, process):
        for message in cache_db.subscribe(self.get_cache_key()):
            try:
                if message == 'stop':
                    process.send_signal(signal.SIGINT)
                elif message == 'force_stop':
                    process.send_signal(signal.SIGKILL)
                elif message == 'stopped':
                    break
            except OSError:
                pass

    def _status_thread(self):
        i = 0
        cur_client_count = 0
        while not self._interrupt:
            # Check interrupt every 0.1s check client count every 1s
            if i == 9:
                i = 0
                self.update_clients()
            else:
                i += 1
            time.sleep(0.1)
        self._clear_iptable_rules()

    def _run_thread(self):
        logger.debug('Starting ovpn process. %r' % {
            'server_id': self.id,
        })
        self._interrupt = False
        try:
            try:
                process = subprocess.Popen(['openvpn', self.ovpn_conf_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                self.push_output(traceback.format_exc())
                logger.exception('Failed to start ovpn process. %r' % {
                    'server_id': self.id,
                })
                self.publish('stopped')
                return
            sub_thread = threading.Thread(target=self._sub_thread,
                args=(process,))
            sub_thread.start()
            status_thread = threading.Thread(target=self._status_thread)
            status_thread.start()
            self.status = True
            self.publish('started')

            while True:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    else:
                        continue
                self.push_output(line)

            self._interrupt = True
            status_thread.join()

            self.status = False
            self.publish('stopped')

            logger.debug('Ovpn process has ended. %r' % {
                'server_id': self.id,
            })
        except:
            self._interrupt = True
            self.publish('stopped')
            raise

    def publish(self, message):
        cache_db.publish(self.get_cache_key(), message)

    def start(self):
        if self.status:
            return
        logger.debug('Starting server. %r' % {
            'server_id': self.id,
        })
        self._generate_ovpn_conf()
        self._enable_ip_forwarding()
        self._set_iptable_rules()

        threading.Thread(target=self._run_thread).start()

        started = False
        for message in cache_db.subscribe(self.get_cache_key(),
                SUB_RESPONSE_TIMEOUT):
            if message == 'started':
                started = True
                break
            elif message == 'stopped':
                raise ValueError('Server failed to start')
        if not started:
            raise ValueError('Server thread failed to return start event.')

    def stop(self):
        if not self.status:
            return
        logger.debug('Stopping server. %r' % {
            'server_id': self.id,
        })

        stopped = False
        cache_db.publish(self.get_cache_key(), 'stop')
        for message in cache_db.subscribe(self.get_cache_key(),
                SUB_RESPONSE_TIMEOUT):
            if message == 'stopped':
                stopped = True
                break
        if not stopped:
            raise ValueError('Server thread failed to return stop event.')

    def force_stop(self):
        if not self.status:
            return
        logger.debug('Forcing stop server. %r' % {
            'server_id': self.id,
        })

        stopped = False
        cache_db.publish(self.get_cache_key(), 'stop')
        for message in cache_db.subscribe(self.get_cache_key(), 2):
            if message == 'stopped':
                stopped = True
                break

        if not stopped:
            stopped = False
            cache_db.publish(self.get_cache_key(), 'force_stop')
            for message in cache_db.subscribe(self.get_cache_key(),
                    SUB_RESPONSE_TIMEOUT):
                if message == 'stopped':
                    stopped = True
                    break

            if not stopped:
                raise ValueError('Server thread failed to return stop event.')

    def push_output(self, output):
        self.call_buffer.create_call('push_output', [output.rstrip('\n')])

    def update_clients(self):
        if not self.status:
            return {}
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

        client_count = len(clients)
        if client_count != self._cur_client_count:
            self._cur_client_count = client_count
            self.call_buffer.create_call('update_clients', [clients])

        self.clients = clients
        return clients

    @staticmethod
    def get_server(id):
        if os.path.isdir(os.path.join(app_server.data_path, id)):
            return Server(id=id)

    @staticmethod
    def get_servers():
        logger.debug('Getting servers.')
        path = os.path.join(app_server.data_path)
        servers = []
        if os.path.isdir(path):
            for server_id in os.listdir(path):
                server = Server.get_server(id=server_id)
                if server:
                    servers.append(server)
        return servers
