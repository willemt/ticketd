#include <stdio.h>
#include <string.h>

typedef struct
{
    int is_ip_address;

    char* ip;
    size_t ip_len;

    char* host;
    size_t host_len;

    char* port;
    size_t port_len;

} addr_parse_result_t;

struct addr_parse
{
    addr_parse_result_t* r;
    int cs;
};

%%{
    machine addr_parse;
    access fsm->;

    action ip_start { fsm->r->ip = (char*)fpc; }
    action ip_end { fsm->r->ip_len = (size_t)(fpc - fsm->r->ip); }
    action host_start { fsm->r->host = (char*)fpc; }
    action host_end { fsm->r->host_len = (size_t)(fpc - fsm->r->host); }
    action port_start { fsm->r->port = (char*)fpc; }
    action port_end { fsm->r->port_len = (size_t)(fpc - fsm->r->port); }

    unreserved  = alnum | "-" | "." | "_" | "~" | "=";
    _digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9";
    num = _digit+;

    ip = num.num.num.num > ip_start % ip_end;
    host = unreserved+ > host_start % host_end;
    port = num+ > port_start % port_end;

    main := (host ':' port) |
            (host) |
            (ip ':' port) |
            (ip);

}%%

%% write data;

static void pp_init(struct addr_parse *fsm, addr_parse_result_t* result)
{
    fsm->r = result;
    %% write init;
}

static void pp_execute(struct addr_parse *fsm, const char *data, size_t len)
{
    const char *p = data;
    const char *pe = data + len;
    const char *eof = data + len;
    %% write exec;
}

static int pp_finish(struct addr_parse *fsm)
{
    if (fsm->cs == addr_parse_error)
        return -1;
    if (fsm->cs >= addr_parse_first_final)
        return 1;
    return 0;
}

int parse_addr(const char *path, size_t len, addr_parse_result_t *result)
{
    struct addr_parse pp;
    pp_init(&pp, result);
    pp_execute(&pp, path, len);
    if (pp_finish(&pp) != 1)
        return -1;
    return 0;
}
