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
#include "lmdb.h"
#include "lmdb_helpers.h"
#include "raft.h"
#include "uv_helpers.h"
#include "bitstream.h"
#include "tpl.h"
#include "container_of.h"
#include "local.h"

#include "usage.c"
#include "addr.c"

#define VERSION "0.1.0"
#define ANYPORT 65535
#define MAX_HTTP_CONNECTIONS 100
#define MAX_PEER_CONNECTIONS 100
#define IPV4_STR_LEN 3 * 4 + 3 + 1
#define PERIOD_MSEC 500
#define RV_BUFLEN 512

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
    // TODO: remove
    int padding[100];
} msg_t;

typedef struct
{
    uv_stream_t* stream;

    /* contain peer's address */
    struct sockaddr_in addr;

    /* gather tpl message */
    tpl_gather_t *gt;

    uv_write_t write;

    /* 1 if connected; 0 otherwise */
    int connected;

    int node_idx;

    /* number of expected entries.
     * this counts down as we consume entries */
    int n_expected_entries;

    msg_t aer;
} peer_connection_t;

typedef struct
{
    raft_server_t* raft;

    /* set of tickets that have been issued */
    MDB_dbi tickets;

    MDB_env *db_env;

    uv_mutex_t raft_lock;

    h2o_globalconf_t cfg;
    h2o_context_t ctx;
} server_t;

options_t opts;
server_t server;
server_t *sv = &server;

static size_t __peer_msg_pack(tpl_node *tn, uv_buf_t *buf, char* ptr)
{
    size_t sz;
    tpl_pack(tn, 0);
    tpl_dump(tn, TPL_GETSIZE, &sz);
    tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, ptr, RV_BUFLEN);
    tpl_free(tn);
    buf->len = sz;
    buf->base = ptr;
    return sz;
}

static int __http_error(h2o_req_t *req, const int status_code,
                        const char* reason)
{
    static h2o_generator_t generator = { NULL, NULL };
    static h2o_iovec_t body = { .base = "", .len = 0 };
    req->res.status = status_code;
    req->res.reason = reason;
    h2o_add_header(&req->pool,
                   &req->res.headers,
                   H2O_TOKEN_CONTENT_LENGTH,
                   H2O_STRLIT("0"));
    h2o_start_response(req, &generator);
    /* force keep-alive */
    req->http1_is_persistent = 1;
    h2o_send(req, &body, 1, 1);
    return 0;
}

static int __http_success(h2o_req_t *req, const int status_code)
{
    static h2o_generator_t generator = { NULL, NULL };
    static h2o_iovec_t body = { .base = "", .len = 0 };
    req->res.status = status_code;
    req->res.reason = "OK";
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, 1);
    return 0;
}

/**
 * @return 0 if not unique; otherwise 1 */
static int __check_if_ticket_exists(unsigned int ticket)
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
        ticket = rand();
    }
    while (__check_if_ticket_exists(ticket));
    return ticket;
}

/**
 * Provide the user with an ID
 */
static int __dispatch(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = { NULL, NULL };

    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
        return -1;

    int e;
    int node = 0;
    unsigned int ticket;

    ticket = 999;//__generate_ticket();

    msg_entry_t entry;
    entry.id = rand();
    entry.data.buf = (void*)&ticket;
    entry.data.len = sizeof(ticket);

    msg_entry_response_t r;

    printf("got ticket %d\n", ticket);
    printf("receiving %d\n",
        *(int*)&ticket);
    printf("receiving %d\n",
        *(int*)entry.data.buf);

    /* block until the entry is committed */
    uv_mutex_lock(&sv->raft_lock);

    e = raft_recv_entry(sv->raft, node, &entry, &r);
    uv_mutex_unlock(&sv->raft_lock);
    if (0 != e)
        return __http_error(req, 500, "BAD");

    if (0 == r.was_committed)
        return __http_error(req, 400, "TRY AGAIN");

    /* serialize id */
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

static void __write_cb(uv_write_t *req, int status)
{
    if (0 != status)
        uv_fatal(status);
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

    //printf("send vote %d\n", conn->connected);

    if (0 == conn->connected)
        return 0;

    uv_buf_t bufs[1];
    char buf[RV_BUFLEN], *ptr = buf;
    msg_t msg = {
        .type              = MSG_REQUESTVOTE,
        .rv                = *m
    };
    tpl_node *tn = tpl_map("S(I$(IIII))", &msg);
    ptr += __peer_msg_pack(tn, &bufs[0], ptr);
    int e = uv_write(&conn->write, conn->stream, bufs, 1, __write_cb);
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

    if (0 == conn->connected)
        return 0;

    int e;

    char buf[RV_BUFLEN], *ptr = buf;
    msg_t msg = {
        .type              = MSG_APPENDENTRIES,
        .ae                = {
            .term          = m->term,
            .leader_id     = m->leader_id,
            .prev_log_idx  = m->prev_log_idx,
            .prev_log_term = m->prev_log_term,
            .leader_commit = m->leader_commit,
            .n_entries     = m->n_entries
        }
    };
    tpl_node *tn = tpl_map("S(I$(IIIIII))", &msg);
    ptr += __peer_msg_pack(tn, bufs, ptr);

//    printf("previous log index %d\n", m->prev_log_idx);

    if (0 < m->n_entries)
    {
        printf("sending ENTRIES %d\n", m->n_entries);
        if (m->entries[0].data.buf)
            printf("BUF: %d\n", *(int*)m->entries[0].data.buf);

        tpl_bin tb = {
            .sz = m->entries[0].data.len,
            .addr = m->entries[0].data.buf
        };

        /* list of entries */
        tn = tpl_map("IB", &m->entries[0].id, &tb);//, m->n_entries);
        size_t sz;
        tpl_pack(tn, 0);
        tpl_dump(tn, TPL_GETSIZE, &sz);
        e = tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, ptr, RV_BUFLEN);
        assert(0 == e);
        bufs[1].len = sz;
        bufs[1].base = ptr;
        printf("%d %d\n", (int)bufs[0].len, (int)bufs[1].len);

        e = uv_write(&conn->write, conn->stream, bufs, 2, __write_cb);
        if (-1 == e)
            uv_fatal(e);

        tpl_free(tn);
    }
    else
    {
        e = uv_write(&conn->write, conn->stream, bufs, 1, __write_cb);
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

    printf("applying size:%d\n", len);

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

static void __peer_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
    buf->len = size;
    buf->base = malloc(size);
}

static int __recv_msg(void *img, size_t sz, void *data)
{
    peer_connection_t* conn = data;
    msg_t m;
    int e;

    uv_buf_t bufs[1];
    char buf[RV_BUFLEN], *ptr = buf;

    if (0 < conn->n_expected_entries)
    {
        msg_entry_t entry;
        tpl_bin tb;

        printf("image: %s %d\n", tpl_peek(TPL_MEM, img, sz), (int)sz);
        printf("expecting entries: %d\n", conn->n_expected_entries);

        //tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &entry.id, &entry.data);
        tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &entry.id, &tb);
        tpl_load(tn, TPL_MEM, img, sz);
        tpl_unpack(tn, 0);

        //printf("binary buffer of length %d at address %p\n", tb.sz, tb.addr);
        if (tb.addr)
            printf("binary buffer %d\n", *(int*)tb.addr);

        entry.data.buf = tb.addr;
        entry.data.len = tb.sz;

        m.ae.entries = &entry;
        msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        e = raft_recv_appendentries(sv->raft, conn->node_idx, &m.ae, &msg.aer);

        tn = tpl_map("S(I$(IIII))", &msg);
        ptr += __peer_msg_pack(tn, &bufs[0], ptr);
        e = uv_write(&conn->write, conn->stream, bufs, 1, __write_cb);
        if (-1 == e)
            uv_fatal(e);

        conn->n_expected_entries = 0;

        return 0;
    }

    /* deserialize message */
    tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &m);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);

    //printf("msg = %d\n", m.type);
    //printf("zzconn->node_idx = %d\n", conn->node_idx);

    /* decide what to do with message */

    switch (m.type)
    {
    case MSG_HANDSHAKE:
        printf("HS HTTP: %d PEER: %d\n", m.hs.http_port, m.hs.peer_port);

        assert(0 == conn->connected);

        int i;

        for (i = 0; i < raft_get_num_nodes(sv->raft); i++)
        {
            raft_node_t* node = raft_get_node(sv->raft, i);
            peer_connection_t* other_conn = raft_node_get_udata(node);
            if (conn->addr.sin_addr.s_addr ==
                other_conn->addr.sin_addr.s_addr &&
                m.hs.peer_port == ntohs(other_conn->addr.sin_port))
            {
                raft_node_set_udata(node, conn);
                //free(other_conn);
                printf("FOUND PEER!\n");
                conn->connected = 1;
                conn->node_idx = i;
            }
        }
        break;
    case MSG_REQUESTVOTE:
    {
        printf("RV term:%d \n", m.rv.term);

        msg_t msg = { .type = MSG_REQUESTVOTE_RESPONSE };
        e = raft_recv_requestvote(sv->raft, conn->node_idx, &m.rv, &msg.rvr);

        tpl_node *tn = tpl_map("S(I$(II))", &msg);
        ptr += __peer_msg_pack(tn, &bufs[0], ptr);
        e = uv_write(&conn->write, conn->stream, bufs, 1, __write_cb);
        if (-1 == e)
            uv_fatal(e);
    }
    break;
    case MSG_REQUESTVOTE_RESPONSE:
        printf("RVR term:%d %d\n", m.rvr.term, m.rvr.vote_granted);
        e = raft_recv_requestvote_response(sv->raft, conn->node_idx, &m.rvr);
        break;
    case MSG_APPENDENTRIES:
        //printf("AE term:%d %d %d\n", m.ae.term, m.ae.n_entries, m.ae.prev_log_idx);

        if (0 < m.ae.n_entries)
            printf("n entries:%d \n", m.ae.n_entries);
        conn->n_expected_entries = m.ae.n_entries;

        if (0 < conn->n_expected_entries)
        {
            memcpy(&conn->aer, &m, sizeof(msg_t));
            return 0;
        }

        msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        e = raft_recv_appendentries(sv->raft, conn->node_idx, &m.ae, &msg.aer);
        tpl_node *tn = tpl_map("S(I$(IIII))", &msg);
        ptr += __peer_msg_pack(tn, &bufs[0], ptr);
        e = uv_write(&conn->write, conn->stream, bufs, 1, __write_cb);
        if (-1 == e)
            uv_fatal(e);
        break;
    case MSG_APPENDENTRIES_RESPONSE:
        //printf("AER term:%d \n", m.aer.term);
        e = raft_recv_appendentries_response(sv->raft, conn->node_idx, &m.aer);
        break;
    default:
        printf("unknown msg\n");
        exit(0);
    }
    return 0;
}

static void __peer_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
    peer_connection_t* conn = tcp->data;

    if (nread < 0)
        switch (nread) {
            case UV__EOF:
                break;
            default:
                uv_fatal(nread);
        }

    if (0 <= nread)
    {
        tpl_gather(TPL_GATHER_MEM, buf->base, nread, &conn->gt, __recv_msg,
                   conn);
    }

//    free(buf.base);
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
    tcp->data = conn;
    conn->stream = (uv_stream_t*)tcp;

    /* get peer's IP */
    int namelen = sizeof(conn->addr);
    e = uv_tcp_getpeername(tcp, (struct sockaddr*)&conn->addr, &namelen);
    if (0 != e)
        uv_fatal(e);

    e = uv_read_start((uv_stream_t*)tcp, __peer_alloc_cb, __peer_read_cb);
    if (0 != e)
        uv_fatal(e);
}

static void __on_connection_accepted_by_peer(uv_connect_t *req,
                                             const int status)
{
    peer_connection_t* conn = req->data;
    int e;

    switch (status)
    {
    case 0:
        conn->connected = 1;
        break;
    case -ECONNREFUSED:
        printf("connected FAILED, try again plz\n");
        return;
    default:
        uv_fatal(status);
    }

    /* send handshake */
    uv_buf_t bufs[1];
    char buf[RV_BUFLEN], *ptr = buf;
    msg_t msg;
    msg.type = MSG_HANDSHAKE;
    msg.hs.peer_port = atoi(opts.peer_port);
    msg.hs.http_port = atoi(opts.http_port);
    tpl_node *tn = tpl_map("S(I$(II))", &msg);
    ptr += __peer_msg_pack(tn, &bufs[0], ptr);
    e = uv_write(&conn->write, conn->stream, bufs, 1, __write_cb);
    if (-1 == e)
        uv_fatal(e);

    /* start reading from peer */
    req->handle->data = req->data;
    e = uv_read_start(req->handle, __peer_alloc_cb, __peer_read_cb);
    if (0 != e)
        uv_fatal(e);
}

static int __connect_to_peer(peer_connection_t* conn, uv_loop_t* loop)
{
    int e;

    conn->stream = malloc(sizeof(uv_tcp_t));
    conn->stream->data = conn;
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

void __raft_log(raft_server_t* raft, void *udata, const char *buf, ...)
{
    printf("log: '%s'\n", buf);
}

raft_cbs_t raft_funcs = {
    .send_requestvote            = __send_requestvote,
    .send_appendentries          = __send_appendentries,
    .applylog                    = __applylog,
    .log                         = __raft_log,
};

static void __periodic(uv_timer_t* handle)
{
    int e;

    e = raft_periodic(sv->raft, PERIOD_MSEC);
}

int main(int argc, char **argv)
{
    int e;

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

    uv_loop_t loop;
    uv_loop_init(&loop);

    sv->raft = raft_new();
    raft_set_callbacks(sv->raft, &raft_funcs, sv);
    // TODO: load commits
    // TODO: load voted for
    // TODO: load term
    // TODO: add option for dropping persisted data

    /* parse list of peers */
    int node_idx = 0;
    char *tok = opts.PEERS;
    while ((tok = strsep(&opts.PEERS, ",")) != NULL)
    {
        addr_parse_result_t res;
        parse_addr(tok, strlen(tok), &res);
        res.host[res.host_len] = '\0';

        printf("%s : %d\n", res.host, atoi(res.port));

        peer_connection_t* conn = calloc(1, sizeof(peer_connection_t));
        conn->node_idx = node_idx;
        e = uv_ip4_addr(res.host, atoi(res.port), &conn->addr);
        if (0 != e)
            uv_fatal(e);

        int peer_is_self = (0 == strcmp(opts.host, res.host) &&
                            opts.peer_port && res.port &&
                            0 == strcmp(opts.peer_port, res.port));

        if (!peer_is_self)
            __connect_to_peer(conn, &loop);

        raft_add_peer(sv->raft, conn, peer_is_self);
        node_idx++;
    }

    uv_mutex_init(&sv->raft_lock);

    signal(SIGPIPE, SIG_IGN);

    /* Ticket DB */
    mdb_db_env_create(&sv->db_env, 0, opts.path, atoi(opts.db_size));
    mdb_db_create(&sv->tickets, sv->db_env, "docs");

    /* Web server for clients */
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
    handler->on_req = __dispatch;

    /* Listen socket for HTTP client traffic */
    uv_tcp_t http_listen;
    h2o_context_init(&sv->ctx, &loop, &sv->cfg);
    uv_bind_listen_socket(&http_listen, opts.host, atoi(opts.http_port), &loop);
    e = uv_listen((uv_stream_t*)&http_listen, MAX_HTTP_CONNECTIONS,
                  __on_http_connection);
    if (0 != e)
        uv_fatal(e);

    /* Listen socket for raft peers */
    uv_tcp_t peer_listen;
    uv_bind_listen_socket(&peer_listen, opts.host, atoi(opts.peer_port), &loop);
    e = uv_listen((uv_stream_t*)&peer_listen, MAX_PEER_CONNECTIONS,
                  __on_peer_connection);
    if (0 != e)
        uv_fatal(e);

    /* Raft periodic timer */
    uv_timer_t *periodic_req;
    periodic_req = malloc(sizeof(uv_timer_t));
    periodic_req->data = sv;
    uv_timer_init(&loop, periodic_req);
    uv_timer_start(periodic_req, __periodic, 0, 500);

    e = uv_run(&loop, UV_RUN_DEFAULT);
    if (0 != e)
        uv_fatal(e);
}
