#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "uv.h"
#include "uv_helpers.h"

void uv_bind_listen_socket(uv_tcp_t* listen, const char* host, const int port, uv_loop_t* loop)
{
    int e;

    e = uv_tcp_init(loop, listen);
    if (e != 0)
        uv_fatal(e);

    struct sockaddr_in addr;
    e = uv_ip4_addr(host, port, &addr);
    switch (e)
    {
        case 0:
            break;
        case EINVAL:
            fprintf(stderr, "Invalid address/port: %s %d\n", host, port);
            abort();
            break;
        default:
        uv_fatal(e);
    }

    e = uv_tcp_bind(listen, (struct sockaddr *)&addr, 0);
    if (e != 0)
        uv_fatal(e);
}
