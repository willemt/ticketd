
#line 1 "src/addr.rl"
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


#line 49 "src/addr.rl"



#line 33 "src/addr.c"
static const char _addr_parse_actions[] = {
	0, 1, 0, 1, 2, 1, 3, 1, 
	4, 1, 5, 2, 3, 1
};

static const char _addr_parse_key_offsets[] = {
	0, 0, 11, 13, 25, 27, 39, 51, 
	63
};

static const char _addr_parse_trans_keys[] = {
	61, 95, 126, 45, 46, 48, 57, 65, 
	90, 97, 122, 48, 57, 58, 61, 95, 
	126, 45, 46, 48, 57, 65, 90, 97, 
	122, 48, 57, 58, 61, 95, 126, 45, 
	46, 48, 57, 65, 90, 97, 122, 58, 
	61, 95, 126, 45, 46, 48, 57, 65, 
	90, 97, 122, 58, 61, 95, 126, 45, 
	46, 48, 57, 65, 90, 97, 122, 58, 
	61, 95, 126, 45, 46, 48, 57, 65, 
	90, 97, 122, 0
};

static const char _addr_parse_single_lengths[] = {
	0, 3, 0, 4, 0, 4, 4, 4, 
	4
};

static const char _addr_parse_range_lengths[] = {
	0, 4, 1, 4, 1, 4, 4, 4, 
	4
};

static const char _addr_parse_index_offsets[] = {
	0, 0, 8, 10, 19, 21, 30, 39, 
	48
};

static const char _addr_parse_indicies[] = {
	0, 0, 0, 0, 2, 0, 0, 1, 
	3, 1, 5, 4, 4, 4, 4, 4, 
	4, 4, 1, 6, 1, 5, 4, 4, 
	4, 4, 7, 4, 4, 1, 5, 4, 
	4, 4, 4, 8, 4, 4, 1, 5, 
	4, 4, 4, 4, 9, 4, 4, 1, 
	10, 4, 4, 4, 4, 9, 4, 4, 
	1, 0
};

static const char _addr_parse_trans_targs[] = {
	3, 0, 5, 4, 3, 2, 4, 6, 
	7, 8, 2
};

static const char _addr_parse_trans_actions[] = {
	3, 0, 3, 7, 0, 5, 0, 0, 
	0, 1, 11
};

static const char _addr_parse_eof_actions[] = {
	0, 0, 0, 5, 9, 5, 5, 5, 
	11
};

static const int addr_parse_start = 1;
static const int addr_parse_first_final = 3;
static const int addr_parse_error = 0;

static const int addr_parse_en_main = 1;


#line 52 "src/addr.rl"

static void pp_init(struct addr_parse *fsm, addr_parse_result_t* result)
{
    fsm->r = result;
    
#line 111 "src/addr.c"
	{
	 fsm->cs = addr_parse_start;
	}

#line 57 "src/addr.rl"
}

static void pp_execute(struct addr_parse *fsm, const char *data, size_t len)
{
    const char *p = data;
    const char *pe = data + len;
    const char *eof = data + len;
    
#line 125 "src/addr.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if (  fsm->cs == 0 )
		goto _out;
_resume:
	_keys = _addr_parse_trans_keys + _addr_parse_key_offsets[ fsm->cs];
	_trans = _addr_parse_index_offsets[ fsm->cs];

	_klen = _addr_parse_single_lengths[ fsm->cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _addr_parse_range_lengths[ fsm->cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _addr_parse_indicies[_trans];
	 fsm->cs = _addr_parse_trans_targs[_trans];

	if ( _addr_parse_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _addr_parse_actions + _addr_parse_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 29 "src/addr.rl"
	{ fsm->r->ip = (char*)p; }
	break;
	case 1:
#line 30 "src/addr.rl"
	{ fsm->r->ip_len = (size_t)(p - fsm->r->ip); }
	break;
	case 2:
#line 31 "src/addr.rl"
	{ fsm->r->host = (char*)p; }
	break;
	case 3:
#line 32 "src/addr.rl"
	{ fsm->r->host_len = (size_t)(p - fsm->r->host); }
	break;
	case 4:
#line 33 "src/addr.rl"
	{ fsm->r->port = (char*)p; }
	break;
#line 219 "src/addr.c"
		}
	}

_again:
	if (  fsm->cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _addr_parse_actions + _addr_parse_eof_actions[ fsm->cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 1:
#line 30 "src/addr.rl"
	{ fsm->r->ip_len = (size_t)(p - fsm->r->ip); }
	break;
	case 3:
#line 32 "src/addr.rl"
	{ fsm->r->host_len = (size_t)(p - fsm->r->host); }
	break;
	case 5:
#line 34 "src/addr.rl"
	{ fsm->r->port_len = (size_t)(p - fsm->r->port); }
	break;
#line 247 "src/addr.c"
		}
	}
	}

	_out: {}
	}

#line 65 "src/addr.rl"
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
