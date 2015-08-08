#ifndef UV_HELPERS_H
#define UV_HELPERS_H

#define uv_fatal(e) { \
        assert(0 != e); \
        fprintf(stderr, "%s:%d - err:%s: %s\n", \
                __FILE__, __LINE__, uv_err_name((e)), uv_strerror((e))); \
        exit(1); }

/**
 * Bind a listen socket
 * Abort if any failure. */
void uv_bind_listen_socket(uv_tcp_t* listen, const char* host, const int port, uv_loop_t* loop);

#endif /* UV_HELPERS_H */
