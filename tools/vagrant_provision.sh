#!/usr/bin/env bash
apt-get update -qq 1> /dev/null

# Dev requirements
apt-get install -qq -y python-flask python-cherrypy3 openvpn htop 1> /dev/null

# Build requirements
apt-get install -qq -y devscripts debhelper python-all python-setuptools 1> /dev/null

# Rng-tools
apt-get install -qq -y rng-tools
echo "HRNGDEVICE=/dev/urandom" > /etc/default/rng-tools
/etc/init.d/rng-tools start
