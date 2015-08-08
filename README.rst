.. image:: http://badges.github.io/stability-badges/dist/experimental.svg
   :target: http://github.com/badges/stability-badges

Distributed durable unique 64bit ID server

What?
=====
ticketd is a distributed durable unique 64bit ID server. The raft protocol is used for consistency.

It uses `LMDB <http://symas.com/mdb/>`_ for storing data, `H2O <https://github.com/h2o/h2o>`_ for HTTP, and `raft <https://github.com/willemt/raft>`_ for concensus.

ticketd is completely written in C.

Warning
=======

*This is experimental!*

Among the many memory leaks, three key raft related features are still in-progress:

* Leader entry re-routing
* Saving persistent state
* Dynamic membership changes

How?
====

ticketed opens 2 ports as follows:

1. HTTP client traffic
2. Peer to peer traffic using a ticketd specific binary protocol

Usage
=====

Examples below make use of the excellent `httpie <https://github.com/jakubroztocil/httpie>`_

Starting
--------

Node A:

.. code-block:: bash

   ticketd 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --peer_port 9001 --http_port 8001

Node B:

.. code-block:: bash

   ticketd 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --peer_port 9002 --http_port 8002

Node C:

.. code-block:: bash

   ticketd 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --peer_port 9003 --http_port 8003

Obtain a unique identifier via HTTP POST
----------------------------------------

.. code-block:: bash

   http --ignore-stdin POST 127.0.0.1:8001

.. code-block:: http
   :class: dotted

   HTTP/1.1 200 OK
   Connection: keep-alive
   Date: Sat, 08 Aug 2015 10:02:07 GMT
   Server: h2o/1.3.1
   transfer-encoding: chunked

   823378840

Building
========

.. code-block:: bash
   :class: ignore

   $ make libuv
   $ make libh2o
   $ make
