pritunl-node: pritunl openvpn server node
=========================================

.. image:: http://gitshields.com/v2/text/license/AGPLv3/blue.png
    :target: https://www.gnu.org/licenses/agpl-3.0.html

`Pritunl-Node <https://github.com/pritunl/pritunl-node>`_ is a node server
that connects to a pritunl server to allow running distributed openvpn servers
controlled by a single pritunl server. Still in development.

Development Setup
-----------------

.. code-block:: bash

    $ git clone https://github.com/pritunl/pritunl-node.git
    $ cd pritunl-node
    $ python2 server.py

Vagrant Setup
-------------

.. code-block:: bash

    $ git clone https://github.com/pritunl/pritunl-node.git
    $ cd pritunl-node
    $ vagrant up
    $ vagrant ssh
    $ cd /vagrant
    $ sudo python2 server.py
