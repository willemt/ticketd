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

Among the many memory leaks, two key raft related features are still in-progress:

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
   :class: ignore

   ticketd 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --peer_port 9001 --http_port 8001

Node B:

.. code-block:: bash
   :class: ignore

   ticketd 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --peer_port 9002 --http_port 8002

Node C:

.. code-block:: bash
   :class: ignore

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

Leader Redirection
------------------

If we try to obtain an identifier from a non-leader, then ticketd will respond with a 301 redirect reponse. The redirect shows the location of the current leader.

Forcing the client to redirect to the leader means that future requests will be faster (ie. no delays are caused by proxying the request).

.. code-block:: bash

   curl --request POST -i -L 127.0.0.1:8003

.. code-block:: http
   :class: dotted

   HTTP/1.1 301 Moved Permanently
   Date: Thu, 13 Aug 2015 16:03:02 GMT
   Server: h2o/1.3.1
   Connection: close
   location: http://127.0.0.1:8001/

   HTTP/1.1 200 OK
   Date: Thu, 13 Aug 2015 16:03:02 GMT
   Server: h2o/1.3.1
   Connection: keep-alive
   transfer-encoding: chunked

   1272863780

Building
========

.. code-block:: bash
   :class: ignore

   $ make libuv
   $ make libh2o
   $ make
