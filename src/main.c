/**
 * Copyright (c) 2015, Willem-Hendrik Thiart
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "h2o.h"
#include "h2o/http1.h"
#include "h2o_helpers.h"
#include "lmdb.h"
#include "lmdb_helpers.h"
#include "raft.h"
#include "uv_helpers.h"
#include "uv_multiplex.h"
#include "tpl.h"

#include "usage.c"
#include "parse_addr.c"

#define VERSION "0.1.0"
#define ANYPORT 65535
#define MAX_HTTP_CONNECTIONS 128
#define MAX_PEER_CONNECTIONS 128
#define IPV4_STR_LEN 3 * 4 + 3 + 1
#define PERIOD_MSEC 500
#define RAFT_BUFLEN 512
#define LEADER_URL_LEN 512
#define IPC_PIPE_NAME "ticketd_ipc"
#define HTTP_WORKERS 2

typedef enum
{
    /** If we are a peer that is attemping a connection need to send a handshake
     * This is because we need to identify ourselves */
    MSG_HANDSHAKE,
    MSG_REQUESTVOTE,
    MSG_REQUESTVOTE_RESPONSE,
    MSG_APPENDENTRIES,
    MSG_APPENDENTRIES_RESPONSE,
} peer_message_type_e;

/**
 * Peer protocol:
 * Send handshake after connecting so that we can identify the peer */
typedef struct
{
    int peer_port;
    int http_port;
} msg_handshake_t;

typedef struct
{
    int type;
    union
    {
        msg_handshake_t hs;
        msg_requestvote_t rv;
        msg_requestvote_response_t rvr;
        msg_appendentries_t ae;
        msg_appendentries_response_t aer;
    };
    int padding[100];
} msg_t;

typedef enum
{
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
} conn_status_e;

typedef struct
{
    /* peer's address */
    struct sockaddr_in addr;

    int http_port;

    /* gather TPL message */
    tpl_gather_t *gt;

    conn_status_e connection_status;

    /* peer's raft node_idx */
    int node_idx;

    /* number of expected entries.
     * this counts down as we consume entries */
    int n_expected_entries;

    /* remember most recent append entries msg, we refer to this msg when we
     * finish reading the log entries
     * used by n_expected_entries */
    msg_t ae;

    uv_stream_t* stream;

    uv_write_t write;

    uv_loop_t* loop;
} peer_connection_t;

typedef struct
{
    raft_server_t* raft;

    /* our raft node index */
    int node_idx;

    /* set of tickets that have been issued */
    MDB_dbi tickets;

    /* persistent state for voted_for and term */
    MDB_dbi state;

    /* entries that have been appended to our log */
    MDB_dbi entries;

    MDB_env *db_env;

    h2o_globalconf_t cfg;
    h2o_context_t ctx;

    uv_mutex_t raft_lock;
    uv_cond_t appendentries_received;
} server_t;

options_t opts;
server_t server;
server_t *sv = &server;

static int __connect_to_peer(peer_connection_t* conn, uv_loop_t* loop);

/**
 * @param[out] bufs libuv buffer to insert serialized message into
 * @param[out] buf Buffer to write serialized message into */
static size_t __peer_msg_serialize(tpl_node *tn, uv_buf_t *buf, char* data)
{
    size_t sz;
    tpl_pack(tn, 0);
    tpl_dump(tn, TPL_GETSIZE, &sz);
    tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, data, RAFT_BUFLEN);
    tpl_free(tn);
    buf->len = sz;
    buf->base = data;
    return sz;
}

/**
 * @return 0 if not unique; otherwise 1 */
static int __check_if_ticket_exists(const unsigned int ticket)
{
    MDB_txn *txn;

    int e = mdb_txn_begin(sv->db_env, NULL, MDB_RDONLY, &txn);
    if (0 != e)
        mdb_fatal(e);

    MDB_val k = { .mv_size = sizeof(ticket), .mv_data = (void*)&ticket };
    MDB_val v;

    e = mdb_get(txn, sv->tickets, &k, &v);
    switch (e)
    {
    case 0:
        break;
    case MDB_NOTFOUND:
        e = mdb_txn_commit(txn);
        if (0 != e)
            mdb_fatal(e);
        return 0;
    default:
        mdb_fatal(e);
    }

    e = mdb_txn_commit(txn);
    if (0 != e)
        mdb_fatal(e);

    return 1;
}

static unsigned int __generate_ticket()
{
    unsigned int ticket;

    do
    {
        // TODO need better random number generator
        ticket = rand();
    }
    while (__check_if_ticket_exists(ticket));
    return ticket;
}

/**
 * HTTP POST /
 * Provide the user with an ID */
static int __http_get_id(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = { NULL, NULL };

    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
        return -1;

    /* redirect to leader if needed */
    int leader = raft_get_current_leader(sv->raft);
    if (-1 == leader)
    {
        return h2oh_respond_with_error(req, 503, "Leader unavailable");
    }
    else if (leader != sv->node_idx)
    {
        raft_node_t* node = raft_get_node(sv->raft, leader);
        peer_connection_t* conn = raft_node_get_udata(node);
        char leader_url[LEADER_URL_LEN];

        static h2o_generator_t generator = { NULL, NULL };
        static h2o_iovec_t body = { .base = "", .len = 0 };
        req->res.status = 301;
        req->res.reason = "Moved Permanently";
        h2o_start_response(req, &generator);
        snprintf(leader_url, LEADER_URL_LEN, "http://%s:%d/",
                 inet_ntoa(conn->addr.sin_addr), conn->http_port);
        h2o_add_header(&req->pool,
                       &req->res.headers,
                       H2O_TOKEN_LOCATION,
                       leader_url,
                       strlen(leader_url));
        h2o_send(req, &body, 1, 1);
        return 0;
    }

    int e;

    unsigned int ticket = __generate_ticket();

    msg_entry_t entry;
    entry.id = rand();
    entry.data.buf = (void*)&ticket;
    entry.data.len = sizeof(ticket);

    uv_mutex_lock(&sv->raft_lock);

    msg_entry_response_t r;
    e = raft_recv_entry(sv->raft, sv->node_idx, &entry, &r);
    if (0 != e)
        return h2oh_respond_with_error(req, 500, "BAD");

    /* block until the entry is committed */
    int done = 0;
    do {
        uv_cond_wait(&sv->appendentries_received, &sv->raft_lock);
        e = raft_msg_entry_response_committed(sv->raft, &r);
        switch (e)
        {
            case 0:
                /* not committed yet */
                break;
            case 1:
                done = 1;
                uv_mutex_unlock(&sv->raft_lock);
                break;
            case -1:
                uv_mutex_unlock(&sv->raft_lock);
                return h2oh_respond_with_error(req, 400, "TRY AGAIN");
        }
    } while (!done);

    /* serialize ID */
    char id_str[100];
    h2o_iovec_t body;
    sprintf(id_str, "%d", entry.id);
    body = h2o_iovec_init(id_str, strlen(id_str));

    req->res.status = 200;
    req->res.reason = "OK";
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, 1);
    return 0;
}

static void __on_http_connection(uv_stream_t *listener, const int status)
{
    int e;

    if (0 != status)
        uv_fatal(status);

    uv_tcp_t *tcp = calloc(1, sizeof(*tcp));
    e = uv_tcp_init(listener->loop, tcp);
    if (0 != status)
        uv_fatal(e);

    e = uv_accept(listener, (uv_stream_t*)tcp);
    if (0 != e)
        uv_fatal(e);

    h2o_socket_t *sock =
        h2o_uv_socket_create((uv_stream_t*)tcp, (uv_close_cb)free);
    h2o_http1_accept(&sv->ctx, sv->cfg.hosts, sock);
}

static void __peer_write_cb(uv_write_t *req, int status)
{
    peer_connection_t* conn = req->data;

    switch (status)
    {
    case 0:
        break;
    case UV__EPIPE:
        conn->connection_status = DISCONNECTED;
        break;
    default:
        uv_fatal(status);
    }
}

static int __connect_if_needed(peer_connection_t* conn)
{
    if (CONNECTED != conn->connection_status)
    {
        if (DISCONNECTED == conn->connection_status)
            __connect_to_peer(conn, conn->loop);
        return -1;
    }
    return 0;
}

static int __send_requestvote(
    raft_server_t* raft,
    void *udata,
    int nodeidx,
    msg_requestvote_t* m
    )
{
    raft_node_t* node = raft_get_node(raft, nodeidx);
    peer_connection_t* conn = raft_node_get_udata(node);

    int e = __connect_if_needed(conn);
    if (-1 == e)
        return 0;

    uv_buf_t bufs[1];
    char buf[RAFT_BUFLEN];
    msg_t msg = {
        .type              = MSG_REQUESTVOTE,
        .rv                = *m
    };
    __peer_msg_serialize(tpl_map("S(I$(IIII))", &msg), bufs, buf);
    conn->write.data = conn;
    e = uv_write(&conn->write, conn->stream, bufs, 1, __peer_write_cb);
    if (-1 == e)
        uv_fatal(e);
    return 0;
}

static int __send_appendentries(
    raft_server_t* raft,
    void *udata,
    int nodeidx,
    msg_appendentries_t* m
    )
{
    uv_buf_t bufs[3];

    raft_node_t* node = raft_get_node(raft, nodeidx);
    peer_connection_t* conn = raft_node_get_udata(node);

    int e = __connect_if_needed(conn);
    if (-1 == e)
        return 0;

    char buf[RAFT_BUFLEN], *ptr = buf;
    msg_t msg = {
        .type              = MSG_APPENDENTRIES,
        .ae                = {
            .term          = m->term,
            .prev_log_idx  = m->prev_log_idx,
            .prev_log_term = m->prev_log_term,
            .leader_commit = m->leader_commit,
            .n_entries     = m->n_entries
        }
    };
    ptr += __peer_msg_serialize(tpl_map("S(I$(IIIII))", &msg), bufs, ptr);

    /* appendentries with payload */
    if (0 < m->n_entries)
    {
        tpl_bin tb = {
            .sz   = m->entries[0].data.len,
            .addr = m->entries[0].data.buf
        };

        /* list of entries */
        tpl_node *tn = tpl_map("IIB", &m->entries[0].id, &m->entries[0].term, &tb);
        size_t sz;
        tpl_pack(tn, 0);
        tpl_dump(tn, TPL_GETSIZE, &sz);
        e = tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, ptr, RAFT_BUFLEN);
        assert(0 == e);
        bufs[1].len = sz;
        bufs[1].base = ptr;

        e = uv_write(&conn->write, conn->stream, bufs, 2, __peer_write_cb);
        if (-1 == e)
            uv_fatal(e);

        tpl_free(tn);
    }
    else
    {
        /* keep alive appendentries only */
        e = uv_write(&conn->write, conn->stream, bufs, 1, __peer_write_cb);
        if (-1 == e)
            uv_fatal(e);
    }

    return 0;
}

static int __applylog(
    raft_server_t* raft,
    void *udata,
    const unsigned char *data,
    const int len
    )
{
    MDB_txn *txn;

    int e = mdb_txn_begin(sv->db_env, NULL, 0, &txn);
    if (0 != e)
        mdb_fatal(e);

    MDB_val key = { .mv_size = len, .mv_data = (void*)data };
    MDB_val val = { .mv_size = 0, .mv_data = "\0" };

    e = mdb_put(txn, sv->tickets, &key, &val, 0);
    switch (e)
    {
    case 0:
        break;
    case MDB_MAP_FULL:
    {
        mdb_txn_abort(txn);
        return -1;
    }
    default:
        mdb_fatal(e);
    }

    e = mdb_txn_commit(txn);
    if (0 != e)
        mdb_fatal(e);

    return 0;
}

static int __persist_term(
    raft_server_t* raft,
    void *udata,
    const int current_term
    )
{
    MDB_txn *txn;

    int e = mdb_txn_begin(sv->db_env, NULL, 0, &txn);
    if (0 != e)
        mdb_fatal(e);

    int term = current_term;
    MDB_val key = { .mv_size = strlen("term"), .mv_data = "term" };
    MDB_val val = { .mv_size = sizeof(int), .mv_data = &term };

    e = mdb_put(txn, sv->state, &key, &val, 0);
    switch (e)
    {
    case 0:
        break;
    default:
        mdb_fatal(e);
    }

    e = mdb_txn_commit(txn);
    if (0 != e)
        mdb_fatal(e);

    return 0;
}

static int __persist_vote(
    raft_server_t* raft,
    void *udata,
    const int voted_for
    )
{
    MDB_txn *txn;

    int e = mdb_txn_begin(sv->db_env, NULL, 0, &txn);
    if (0 != e)
        mdb_fatal(e);

    int vote = voted_for;
    MDB_val key = { .mv_size = strlen("voted_for"), .mv_data = "voted_for" };
    MDB_val val = { .mv_size = sizeof(int), .mv_data = &vote };

    e = mdb_put(txn, sv->state, &key, &val, 0);
    switch (e)
    {
    case 0:
        break;
    default:
        mdb_fatal(e);
    }

    e = mdb_txn_commit(txn);
    if (0 != e)
        mdb_fatal(e);

    return 0;
}

static void __peer_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
    buf->len = size;
    buf->base = malloc(size);
}

static void __deserialize_appendentries_payload(msg_entry_t* out,
                                                peer_connection_t* conn,
                                                void *img, size_t sz)
{
    tpl_bin tb;

    tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &out->id, &out->term, &tb);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);

    out->data.buf = tb.addr;
    out->data.len = tb.sz;
}

/**
 * Parse raft traffic using binary protocol, and respond to message */
static int __deserialize_and_handle_msg(void *img, size_t sz, void *data)
{
    peer_connection_t* conn = data;
    msg_t m;
    int e;

    uv_buf_t bufs[1];
    char buf[RAFT_BUFLEN], *ptr = buf;

    /* special case: handle appendentries payload */
    if (0 < conn->n_expected_entries)
    {
        msg_entry_t entry;

        __deserialize_appendentries_payload(&entry, conn, img, sz);

        conn->ae.ae.entries = &entry;
        msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        int e = raft_recv_appendentries(sv->raft, conn->node_idx, &conn->ae.ae,
                                        &msg.aer);

        /* send response */
        uv_buf_t bufs[1];
        char buf[RAFT_BUFLEN], *ptr = buf;
        ptr += __peer_msg_serialize(tpl_map("S(I$(IIII))", &msg), bufs, ptr);
        e = uv_write(&conn->write, conn->stream, bufs, 1, __peer_write_cb);
        if (-1 == e)
            uv_fatal(e);

        conn->n_expected_entries = 0;
        return 0;
    }

    /* deserialize message */
    tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &m);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);

    /* handle message */
    switch (m.type)
    {
    case MSG_HANDSHAKE:
    {
        int i;

        /* find raft peer for this connection */
        for (i = 0; i < raft_get_num_nodes(sv->raft); i++)
        {
            raft_node_t* node = raft_get_node(sv->raft, i);
            peer_connection_t* other_conn = raft_node_get_udata(node);
            if (conn->addr.sin_addr.s_addr ==
                other_conn->addr.sin_addr.s_addr &&
                m.hs.peer_port == ntohs(other_conn->addr.sin_port))
            {
                conn->http_port = m.hs.http_port;
                conn->connection_status = CONNECTED;
                conn->node_idx = i;
                conn->addr.sin_port = other_conn->addr.sin_port;
                if (conn != other_conn)
                {
                    raft_node_set_udata(node, conn);
                    free(other_conn);
                }
                // TODO: free libuv resources
                return 0;
            }
        }
    }
    break;
    case MSG_REQUESTVOTE:
    {
        msg_t msg = { .type = MSG_REQUESTVOTE_RESPONSE };
        e = raft_recv_requestvote(sv->raft, conn->node_idx, &m.rv, &msg.rvr);

        /* send response */
        ptr += __peer_msg_serialize(tpl_map("S(I$(II))", &msg), bufs, ptr);
        e = uv_write(&conn->write, conn->stream, bufs, 1, __peer_write_cb);
        if (-1 == e)
            uv_fatal(e);
    }
    break;
    case MSG_REQUESTVOTE_RESPONSE:
        e = raft_recv_requestvote_response(sv->raft, conn->node_idx, &m.rvr);
        break;
    case MSG_APPENDENTRIES:
        /* special case: get ready to handle appendentries payload */
        if (0 < m.ae.n_entries)
        {
            conn->n_expected_entries = m.ae.n_entries;
            memcpy(&conn->ae, &m, sizeof(msg_t));
            return 0;
        }

        /* this is a keep alive message */
        msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        e = raft_recv_appendentries(sv->raft, conn->node_idx, &m.ae, &msg.aer);

        /* send response */
        ptr += __peer_msg_serialize(tpl_map("S(I$(IIII))", &msg), bufs, ptr);
        e = uv_write(&conn->write, conn->stream, bufs, 1, __peer_write_cb);
        if (-1 == e)
            uv_fatal(e);
        break;
    case MSG_APPENDENTRIES_RESPONSE:
        e = raft_recv_appendentries_response(sv->raft, conn->node_idx, &m.aer);
        uv_cond_signal(&sv->appendentries_received);
        break;
    default:
        printf("unknown msg\n");
        exit(0);
    }
    return 0;
}

/**
 * Read raft traffic using binary protocol */
static void __peer_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
    peer_connection_t* conn = tcp->data;

    if (nread < 0)
        switch (nread)
        {
        case UV__ECONNRESET:
        case UV__EOF:
            conn->connection_status = DISCONNECTED;
            return;
        default:
            uv_fatal(nread);
        }

    if (0 <= nread)
    {
        uv_mutex_lock(&sv->raft_lock);
        tpl_gather(TPL_GATHER_MEM, buf->base, nread, &conn->gt,
                   __deserialize_and_handle_msg, conn);
        uv_mutex_unlock(&sv->raft_lock);
    }
}

static void __send_handshake(peer_connection_t* conn)
{
    uv_buf_t bufs[1];
    char buf[RAFT_BUFLEN];
    msg_t msg;
    msg.type = MSG_HANDSHAKE;
    msg.hs.peer_port = atoi(opts.peer_port);
    msg.hs.http_port = atoi(opts.http_port);
    __peer_msg_serialize(tpl_map("S(I$(II))", &msg), bufs, buf);
    int e = uv_write(&conn->write, conn->stream, bufs, 1, __peer_write_cb);
    if (-1 == e)
        uv_fatal(e);
}

/**
 * Raft peer has connected to us */
static void __on_peer_connection(uv_stream_t *listener, const int status)
{
    int e;

    if (0 != status)
        uv_fatal(status);

    uv_tcp_t *tcp = calloc(1, sizeof(uv_tcp_t));
    e = uv_tcp_init(listener->loop, tcp);
    if (0 != e)
        uv_fatal(e);

    e = uv_accept(listener, (uv_stream_t*)tcp);
    if (0 != e)
        uv_fatal(e);

    peer_connection_t* conn = calloc(1, sizeof(peer_connection_t));
    conn->node_idx = -1;
    conn->loop = listener->loop;
    conn->stream = (uv_stream_t*)tcp;
    tcp->data = conn;

    int namelen = sizeof(conn->addr);
    e = uv_tcp_getpeername(tcp, (struct sockaddr*)&conn->addr, &namelen);
    if (0 != e)
        uv_fatal(e);

    __send_handshake(conn);

    e = uv_read_start((uv_stream_t*)tcp, __peer_alloc_cb, __peer_read_cb);
    if (0 != e)
        uv_fatal(e);
}

/**
 * Our connection attempt to raft peer has succeeded */
static void __on_connection_accepted_by_peer(uv_connect_t *req,
                                             const int status)
{
    peer_connection_t* conn = req->data;
    int e;

    switch (status)
    {
    case 0:
        break;
    case -ECONNREFUSED:
        return;
    default:
        uv_fatal(status);
    }

    __send_handshake(conn);

    /* start reading from peer */
    conn->connection_status = CONNECTED;
    req->handle->data = req->data;
    e = uv_read_start(req->handle, __peer_alloc_cb, __peer_read_cb);
    if (0 != e)
        uv_fatal(e);
}

/**
 * Connect to raft peer */
static int __connect_to_peer(peer_connection_t* conn, uv_loop_t* loop)
{
    int e;

    conn->stream = malloc(sizeof(uv_tcp_t));
    conn->stream->data = conn;
    conn->connection_status = CONNECTING;
    e = uv_tcp_init(loop, (uv_tcp_t*)conn->stream);
    if (0 != e)
        uv_fatal(e);

    uv_connect_t *c = malloc(sizeof(uv_connect_t));
    c->data = conn;
    e = uv_tcp_connect(c, (uv_tcp_t*)conn->stream,
                       (struct sockaddr*)&conn->addr,
                       __on_connection_accepted_by_peer);
    if (0 != e)
        uv_fatal(e);

    return 0;
}

void __raft_log(raft_server_t* raft, void *udata, const char *buf)
{
    printf("raft: '%s'\n", buf);
}

/**
 * Offer adds an item to the log */
static int __raft_logentry_offer(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *ety,
    int ety_idx
    )
{
    MDB_txn *txn;

    int e = mdb_txn_begin(sv->db_env, NULL, 0, &txn);
    if (0 != e)
        mdb_fatal(e);

    uv_buf_t bufs[1];
    char buf[RAFT_BUFLEN];
    __peer_msg_serialize(tpl_map("S(IIII)", ety), bufs, buf);

    /* 1. put metadata */
    ety_idx <<= 1;
    MDB_val key = { .mv_size = sizeof(ety_idx), .mv_data = (void*)&ety_idx };
    MDB_val val = { .mv_size = bufs->len, .mv_data = bufs->base };

    e = mdb_put(txn, sv->entries, &key, &val, 0);
    switch (e)
    {
    case 0:
        break;
    case MDB_MAP_FULL:
    {
        mdb_txn_abort(txn);
        return -1;
    }
    default:
        mdb_fatal(e);
    }

    /* 2. put entry */
    ety_idx |= 1;
    key.mv_size = sizeof(ety_idx);
    key.mv_data = (void*)&ety_idx;
    val.mv_size = bufs->len;
    val.mv_data = bufs->base;

    e = mdb_put(txn, sv->entries, &key, &val, 0);
    switch (e)
    {
    case 0:
        break;
    case MDB_MAP_FULL:
    {
        mdb_txn_abort(txn);
        return -1;
    }
    default:
        mdb_fatal(e);
    }

    e = mdb_txn_commit(txn);
    if (0 != e)
        mdb_fatal(e);

    return 0;
}

static int __raft_logentry_poll(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    int ety_idx
    )
{
    MDB_val k, v;

    mdb_poll(sv->db_env, sv->entries, &k, &v);

    return 0;
}

static int __raft_logentry_pop(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    int ety_idx
    )
{
    MDB_val k, v;

    mdb_pop(sv->db_env, sv->entries, &k, &v);

    return 0;
}

raft_cbs_t raft_funcs = {
    .send_requestvote            = __send_requestvote,
    .send_appendentries          = __send_appendentries,
    .applylog                    = __applylog,
    .persist_vote                = __persist_vote,
    .persist_term                = __persist_term,
    .log_offer                   = __raft_logentry_offer,
    .log_poll                    = __raft_logentry_poll,
    .log_pop                     = __raft_logentry_pop,
    .log                         = __raft_log,
};

static void __periodic(uv_timer_t* handle)
{
    raft_periodic(sv->raft, PERIOD_MSEC);
}

static void __load_commit_log()
{
    MDB_cursor* curs;
    MDB_txn *txn;
    MDB_val k, v;
    int e;

    e = mdb_txn_begin(sv->db_env, NULL, MDB_RDONLY, &txn);
    if (0 != e)
        mdb_fatal(e);

    e = mdb_cursor_open(txn, sv->entries, &curs);
    if (0 != e)
        mdb_fatal(e);

    e = mdb_cursor_get(curs, &k, &v, MDB_FIRST);
    switch (e)
    {
    case 0:
        break;
    case MDB_NOTFOUND:
        return;
    default:
        mdb_fatal(e);
    }

    raft_entry_t ety;

    int n_entries = 0;

    do
    {
        if (!(*(int*)k.mv_data & 1))
        {
            /* load metadata */
            tpl_node *tn =
                tpl_map(tpl_peek(TPL_MEM, v.mv_data, v.mv_size), &ety);
            tpl_load(tn, TPL_MEM, v.mv_data, v.mv_size);
            tpl_unpack(tn, 0);
        }
        else
        {
            /* load entry */
            ety.data.buf = v.mv_data;
            ety.data.len = v.mv_size;
            raft_append_entry(sv->raft, &ety);
            n_entries++;
        }

        e = mdb_cursor_get(curs, &k, &v, MDB_NEXT);
    }
    while (0 == e);

    mdb_cursor_close(curs);

    e = mdb_txn_commit(txn);
    if (0 != e)
        mdb_fatal(e);

    printf("Entries loaded: %d\n", n_entries);
}

static void __load_persistent_state()
{
    MDB_val val;

    mdb_gets(sv->db_env, sv->state, "voted_for", &val);
    if (val.mv_data)
        raft_vote(sv->raft, *(int*)val.mv_data);

    mdb_gets(sv->db_env, sv->state, "term", &val);
    if (val.mv_data)
        raft_set_current_term(sv->raft, *(int*)val.mv_data);
}

static void __http_worker_start(void* uv_tcp)
{
    assert(uv_tcp);

    uv_tcp_t* listener = uv_tcp;
    //_thread_t* thread = listener->data;

    h2o_context_init(&sv->ctx, listener->loop, &sv->cfg);

    int e = uv_listen((uv_stream_t*)listener, MAX_HTTP_CONNECTIONS, __on_http_connection);
    if (e != 0)
        uv_fatal(e);

    while (1)
        uv_run(listener->loop, UV_RUN_DEFAULT);
}

int main(int argc, char **argv)
{
    int e, i;

    e = parse_options(argc, argv, &opts);
    if (-1 == e)
        exit(-1);
    else if (opts.help)
    {
        show_usage();
        exit(0);
    }
    else if (opts.version)
    {
        fprintf(stdout, "%s\n", VERSION);
        exit(0);
    }

    signal(SIGPIPE, SIG_IGN);

    uv_loop_t loop;
    e = uv_loop_init(&loop);
    if (0 != e)
        uv_fatal(e);

    sv->raft = raft_new();
    raft_set_callbacks(sv->raft, &raft_funcs, sv);

    srand(time(NULL));

    // TODO: add option for dropping persisted data

    /* ticket DB */
    mdb_db_env_create(&sv->db_env, 0, opts.path, atoi(opts.db_size));
    mdb_db_create(&sv->entries, sv->db_env, "entries");
    mdb_db_create(&sv->tickets, sv->db_env, "docs");
    mdb_db_create(&sv->state, sv->db_env, "state");

    __load_persistent_state();
    __load_commit_log();

    /* web server for clients */
    h2o_pathconf_t *pathconf;
    h2o_handler_t *handler;
    h2o_hostconf_t *hostconf;

    h2o_config_init(&sv->cfg);
    hostconf = h2o_config_register_host(&sv->cfg,
                                        h2o_iovec_init(H2O_STRLIT("default")),
                                        ANYPORT);
    pathconf = h2o_config_register_path(hostconf, "/");
    h2o_chunked_register(pathconf);
    handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = __http_get_id;

    uv_mutex_init(&sv->raft_lock);
    uv_cond_init(&sv->appendentries_received);

    /* listen socket for HTTP client traffic */
    uv_tcp_t http_listen;
    uv_bind_listen_socket(&http_listen, opts.host, atoi(opts.http_port), &loop);

    /* http workers */
    uv_multiplex_t m;
    uv_multiplex_init(&m, &http_listen, IPC_PIPE_NAME, HTTP_WORKERS, __http_worker_start);
    for (i = 0; i < HTTP_WORKERS; i++)
        uv_multiplex_worker_create(&m, i, NULL);
    uv_multiplex_dispatch(&m);

    uv_loop_t peer_loop;
    e = uv_loop_init(&peer_loop);
    if (0 != e)
        uv_fatal(e);

    /* parse list of raft peers */
    int node_idx = 0;
    char *tok = opts.PEERS;
    while ((tok = strsep(&opts.PEERS, ",")) != NULL)
    {
        addr_parse_result_t res;
        parse_addr(tok, strlen(tok), &res);
        res.host[res.host_len] = '\0';

        peer_connection_t* conn = calloc(1, sizeof(peer_connection_t));
        conn->node_idx = node_idx;
        conn->loop = &peer_loop;
        e = uv_ip4_addr(res.host, atoi(res.port), &conn->addr);
        if (0 != e)
            uv_fatal(e);

        int peer_is_self = (0 == strcmp(opts.host, res.host) &&
                            opts.peer_port && res.port &&
                            0 == strcmp(opts.peer_port, res.port));

        if (peer_is_self)
            sv->node_idx = node_idx;
        else
            __connect_to_peer(conn, conn->loop);

        raft_add_peer(sv->raft, conn, peer_is_self);
        node_idx++;
    }

    /* listen socket for raft peers */
    uv_tcp_t peer_listen;
    uv_bind_listen_socket(&peer_listen, opts.host, atoi(opts.peer_port), &peer_loop);
    e = uv_listen((uv_stream_t*)&peer_listen, MAX_PEER_CONNECTIONS,
                  __on_peer_connection);
    if (0 != e)
        uv_fatal(e);

    /* raft periodic timer */
    uv_timer_t *periodic_req;
    periodic_req = malloc(sizeof(uv_timer_t));
    periodic_req->data = sv;
    uv_timer_init(&peer_loop, periodic_req);
    uv_timer_start(periodic_req, __periodic, 0, 1000);
    raft_set_election_timeout(sv->raft, 1000);

    while (1)
        uv_run(&peer_loop, UV_RUN_DEFAULT);
}
