from setuptools import setup
import os
import sys
import copy
import shlex
import shutil
import fileinput
import pritunl_node

PATCH_DIR = 'build'
INSTALL_UPSTART = True
INSTALL_SYSTEMD = True

prefix = sys.prefix
for arg in copy.copy(sys.argv):
    if arg.startswith('--prefix'):
        prefix = os.path.normpath(shlex.split(arg)[0].split('=')[-1])
    elif arg == '--no-upstart':
        sys.argv.remove('--no-upstart')
        INSTALL_UPSTART = False
    elif arg == '--no-systemd':
        sys.argv.remove('--no-systemd')
        INSTALL_SYSTEMD = False

if not os.path.exists('build'):
    os.mkdir('build')

data_files = [
    ('/etc', ['data/etc/pritunl-node.conf']),
    ('/var/log', ['data/var/pritunl-node.log']),
]

patch_files = []
if INSTALL_UPSTART:
    patch_files.append('%s/pritunl-node.conf' % PATCH_DIR)
    data_files.append(('/etc/init', ['%s/pritunl-node.conf' % PATCH_DIR]))
    shutil.copy('data/init/pritunl-node.conf',
        '%s/pritunl-node.conf' % PATCH_DIR)
if INSTALL_SYSTEMD:
    patch_files.append('%s/pritunl-node.service' % PATCH_DIR)
    data_files.append(('/etc/systemd/system',
        ['%s/pritunl-node.service' % PATCH_DIR]))
    shutil.copy('data/systemd/pritunl-node.service',
        '%s/pritunl-node.service' % PATCH_DIR)

for file_name in patch_files:
    for line in fileinput.input(file_name, inplace=True):
        line = line.replace('%PREFIX%', prefix)
        print line.rstrip('\n')

setup(
    name='pritunl_node',
    version=pritunl_node.__version__,
    description='Pritunl openvpn server node',
    long_description=open('README.rst').read(),
    author='Zachary Huff',
    author_email='zach.huff.386@gmail.com',
    url='https://github.com/pritunl/pritunl-node',
    download_url='https://github.com/pritunl/pritunl-node/' + \
        'archive/%s.tar.gz' % pritunl_node.__version__,
    keywords='pritunl, openvpn, vpn, management, server',
    packages=['pritunl_node'],
    license=open('LICENSE').read(),
    zip_safe=False,
    install_requires=[
        'tornado>=2.1.0',
    ],
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'pritunl-node = pritunl_node.__main__:pritunl_daemon'],
    },
    platforms=[
        'Linux',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
    ],
)
