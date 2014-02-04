APP_NAME = 'pritunl_node'

SAVED = 'saved'
UNSAVED = 'unsaved'

CALL_QUEUE_MAX = 256
SERVER_PORT = 9800
SUB_RESPONSE_TIMEOUT = 15
THREAD_EVENT_TIMEOUT = 15
CALL_RESPONSE_TIMEOUT = 5
DEFAULT_CONF_PATH = '/etc/pritunl-node.conf'
DEFAULT_DATA_PATH = '/var/lib/pritunl-node'
SERVER_CERT_NAME = 'server.crt'
SERVER_KEY_NAME = 'server.key'
OVPN_CONF_NAME = 'openvpn.conf'
OVPN_STATUS_NAME = 'status'
IFC_POOL_NAME = 'ifc_pool'
AUTH_LOG_NAME = 'auth.log'
CONF_TEMP_EXT = '.tmp'
TLS_VERIFY_NAME = 'tls_verify.py'
USER_PASS_VERIFY_NAME = 'user_pass_verify.py'
CLIENT_CONNECT_NAME = 'client_connect.py'
CLIENT_DISCONNECT_NAME = 'client_disconnect.py'
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# Script will run in python 2 and 3
TLS_VERIFY_SCRIPT = """#!/usr/bin/env python
import os
import sys
import json
import time
import traceback

VALID_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
auth_log_path = '%s'
def log_write(line):
    with open(auth_log_path, 'a') as auth_log_file:
        auth_log_file.write('[TLS_VERIFY][TIME=%%s]%%s\\n' %% (
            int(time.time()), line.rstrip('\\n')))

try:
    try:
        from urllib2 import urlopen
    except ImportError:
        from urllib.request import urlopen
    try:
        from urllib2 import Request
    except ImportError:
        from urllib.request import Request
    try:
        from urllib2 import HTTPError
    except ImportError:
        from urllib.error import HTTPError
    try:
        from socket import error as SocketError
    except ImportError:
        SocketError = ConnectionResetError

    # Get org and common_name from argv
    arg = sys.argv[2]
    arg = ''.join(x for x in arg if x in VALID_CHARS)
    o_index = arg.find('O=')
    cn_index = arg.find('CN=')
    if o_index < 0 or cn_index < 0:
        log_write('[FAILED] Missing organization or user id from args')
        exit(1)
    if o_index > cn_index:
        org = arg[o_index + 2:]
        common_name = arg[3:o_index]
    else:
        org = arg[2:cn_index]
        common_name = arg[cn_index + 3:]
    if not org or not common_name:
        log_write('[FAILED] Missing organization or user id from args')
        exit(1)

    try:
        request = Request('%s://localhost:%s' + \\
            '/server/%s/tls_verify')
        request.add_header('Content-Type', 'application/json')
        response = urlopen(request, json.dumps({
            'org_id': org,
            'user_id': common_name,
        }).encode('utf-8'))
        response = json.loads(response.read().decode('utf-8'))

        if not response['authenticated']:
            log_write('[FAILED] Invalid user id or organization id')
            exit(1)
    except HTTPError as error:
        log_write('[FAILED] Verification server returned error: %%s - %%s' %% (
            error.code, error.reason))
        exit(1)
    except SocketError:
        log_write('[FAILED] Verification server returned socket error')
        exit(1)
except SystemExit:
    raise
except:
    log_write('[EXCEPTION] ' + traceback.format_exc())
    raise

exit(0)
"""

# Script will run in python 2 and 3
USER_PASS_VERIFY_SCRIPT = """#!/usr/bin/env python
import os
import sys
import json
import time
import traceback

VALID_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
auth_log_path = '%s'
def log_write(line):
    with open(auth_log_path, 'a') as auth_log_file:
        auth_log_file.write('[OTP_VERIFY][TIME=%%s]%%s\\n' %% (
            int(time.time()), line.rstrip('\\n')))

try:
    try:
        from urllib2 import urlopen
    except ImportError:
        from urllib.request import urlopen
    try:
        from urllib2 import Request
    except ImportError:
        from urllib.request import Request
    try:
        from urllib2 import HTTPError
    except ImportError:
        from urllib.error import HTTPError
    try:
        from socket import error as SocketError
    except ImportError:
        SocketError = ConnectionResetError

    # Get org and common_name from environ
    tls_env = os.environ.get('tls_id_0')
    if not tls_env:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')
    tls_env = ''.join(x for x in tls_env if x in VALID_CHARS)
    o_index = tls_env.find('O=')
    cn_index = tls_env.find('CN=')
    if o_index < 0 or cn_index < 0:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')
    if o_index > cn_index:
        org = tls_env[o_index + 2:]
        common_name = tls_env[3:o_index]
    else:
        org = tls_env[2:cn_index]
        common_name = tls_env[cn_index + 3:]
    if not org or not common_name:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')

    # Get username and password from input file
    with open(sys.argv[1], 'r') as auth_file:
        username, password = [x.strip() for x in auth_file.readlines()[:2]]
    password = password[:6]
    if not password.isdigit():
        log_write('[ORG=%%s][UID=%%s][FAILED] Authenticator code invalid' %% (
            org, common_name))
        raise TypeError('Authenticator code is invalid')

    try:
        request = Request('%s://localhost:%s' + \\
            '/server/%s/otp_verify')
        request.add_header('Content-Type', 'application/json')
        response = urlopen(request, json.dumps({
            'org_id': org,
            'user_id': common_name,
            'otp_code': password,
        }).encode('utf-8'))
        response = json.loads(response.read().decode('utf-8'))

        if not response['authenticated']:
            log_write('[FAILED] Invalid user id or organization id')
            exit(1)
    except HTTPError as error:
        log_write('[FAILED] Verification server returned error: %%s - %%s' %% (
            error.code, error.reason))
        exit(1)
    except SocketError:
        log_write('[FAILED] Verification server returned socket error')
        exit(1)
except SystemExit:
    raise
except:
    log_write('[EXCEPTION] ' + traceback.format_exc())
    raise

exit(0)
"""

# Script will run in python 2 and 3
CLIENT_CONNECT_SCRIPT = """#!/usr/bin/env python
import os
import sys
import json
import time
import traceback

VALID_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
auth_log_path = '%s'
def log_write(line):
    with open(auth_log_path, 'a') as auth_log_file:
        auth_log_file.write('[CLIENT_CONNECT][TIME=%%s]%%s\\n' %% (
            int(time.time()), line.rstrip('\\n')))

try:
    try:
        from urllib2 import urlopen
    except ImportError:
        from urllib.request import urlopen
    try:
        from urllib2 import Request
    except ImportError:
        from urllib.request import Request
    try:
        from urllib2 import HTTPError
    except ImportError:
        from urllib.error import HTTPError
    try:
        from socket import error as SocketError
    except ImportError:
        SocketError = ConnectionResetError

    # Get org and common_name from environ
    tls_env = os.environ.get('tls_id_0')
    if not tls_env:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')
    tls_env = ''.join(x for x in tls_env if x in VALID_CHARS)
    o_index = tls_env.find('O=')
    cn_index = tls_env.find('CN=')
    if o_index < 0 or cn_index < 0:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')
    if o_index > cn_index:
        org = tls_env[o_index + 2:]
        common_name = tls_env[3:o_index]
    else:
        org = tls_env[2:cn_index]
        common_name = tls_env[cn_index + 3:]
    if not org or not common_name:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')

    try:
        request = Request('%s://localhost:%s' + \\
            '/server/%s/client_connect')
        request.add_header('Content-Type', 'application/json')
        response = urlopen(request, json.dumps({
            'org_id': org,
            'user_id': common_name,
        }).encode('utf-8'))
        response = json.loads(response.read().decode('utf-8'))

        if response['client_conf']:
            with open(sys.argv[1], 'w') as client_conf_file:
                client_conf_file.write(response['client_conf'])
    except HTTPError as error:
        log_write('[FAILED] Server returned error: %%s - %%s' %% (
            error.code, error.reason))
        exit(1)
    except SocketError:
        log_write('[FAILED] Server returned socket error')
        exit(1)
except SystemExit:
    raise
except:
    log_write('[EXCEPTION] ' + traceback.format_exc())
    raise

exit(0)
"""

# Script will run in python 2 and 3
CLIENT_DISCONNECT_SCRIPT = """#!/usr/bin/env python
import os
import sys
import json
import time
import traceback

VALID_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789='
auth_log_path = '%s'
def log_write(line):
    with open(auth_log_path, 'a') as auth_log_file:
        auth_log_file.write('[CLIENT_DISCONNECT][TIME=%%s]%%s\\n' %% (
            int(time.time()), line.rstrip('\\n')))

try:
    try:
        from urllib2 import urlopen
    except ImportError:
        from urllib.request import urlopen
    try:
        from urllib2 import Request
    except ImportError:
        from urllib.request import Request
    try:
        from urllib2 import HTTPError
    except ImportError:
        from urllib.error import HTTPError
    try:
        from socket import error as SocketError
    except ImportError:
        SocketError = ConnectionResetError

    # Get org and common_name from environ
    tls_env = os.environ.get('tls_id_0')
    if not tls_env:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')
    tls_env = ''.join(x for x in tls_env if x in VALID_CHARS)
    o_index = tls_env.find('O=')
    cn_index = tls_env.find('CN=')
    if o_index < 0 or cn_index < 0:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')
    if o_index > cn_index:
        org = tls_env[o_index + 2:]
        common_name = tls_env[3:o_index]
    else:
        org = tls_env[2:cn_index]
        common_name = tls_env[cn_index + 3:]
    if not org or not common_name:
        log_write('[FAILED] Missing organization or user id from environ')
        raise AttributeError('Missing organization or user id from environ')

    try:
        request = Request('%s://localhost:%s' + \\
            '/server/%s/client_disconnect')
        request.add_header('Content-Type', 'application/json')
        response = urlopen(request, json.dumps({
            'org_id': org,
            'user_id': common_name,
        }).encode('utf-8'))
    except HTTPError as error:
        log_write('[FAILED] Server returned error: %%s - %%s' %% (
            error.code, error.reason))
        exit(1)
    except SocketError:
        log_write('[FAILED] Server returned socket error')
        exit(1)
except SystemExit:
    raise
except:
    log_write('[EXCEPTION] ' + traceback.format_exc())
    raise

exit(0)
"""
