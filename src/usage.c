
#line 1 "src/usage.rl"
#include <stdio.h>
#include <string.h>

#define BUFLEN 1024
#define BUFSIZE 2048

typedef struct
{
    /* commands */
    int drop;

    /* flags */
    int daemonize;
    int debug;
    int help;
    int version;

    /* options */
    char* db_size;
    char* host;
    char* http_port;
    char* path;
    char* pid_file;
    char* raft_port;

    /* arguments */
    char* PEERS;

} options_t;

struct params
{
    options_t* opt;
    char buffer[BUFLEN + 1];
    int buflen;
    int cs;
};


#line 81 "src/usage.rl"



#line 47 "src/usage.c"
static const char _params_actions[] = {
	0, 1, 0, 1, 4, 1, 5, 2, 
	1, 8, 2, 1, 9, 2, 1, 10, 
	2, 1, 11, 2, 1, 12, 2, 1, 
	13, 2, 1, 14, 2, 2, 0, 3, 
	1, 14, 3, 3, 1, 14, 6, 3, 
	1, 14, 7
};

static const char _params_key_offsets[] = {
	0, 0, 3, 4, 13, 17, 20, 21, 
	22, 23, 24, 25, 26, 27, 28, 29, 
	30, 31, 32, 33, 34, 35, 36, 37, 
	38, 39, 40, 42, 43, 44, 45, 46, 
	47, 48, 49, 50, 51, 52, 53, 54, 
	55, 56, 57, 59, 60, 61, 62, 63, 
	64, 65, 66, 67, 68, 69, 70, 71, 
	72, 73, 74, 75, 76, 77, 78, 79, 
	80, 81, 82, 83, 84, 88, 91, 93, 
	95, 97, 98, 100, 102, 104, 106, 108, 
	110, 111, 113, 115, 117, 118
};

static const char _params_trans_keys[] = {
	0, 45, 100, 0, 45, 72, 80, 100, 
	103, 105, 112, 115, 116, 100, 104, 112, 
	114, 97, 98, 101, 101, 109, 111, 110, 
	105, 122, 101, 0, 95, 115, 105, 122, 
	101, 0, 0, 0, 98, 117, 103, 0, 
	111, 116, 115, 116, 0, 0, 0, 116, 
	112, 95, 112, 111, 114, 116, 0, 0, 
	0, 97, 105, 116, 104, 0, 0, 0, 
	100, 95, 102, 105, 108, 101, 0, 0, 
	0, 97, 102, 116, 95, 112, 111, 114, 
	116, 0, 0, 0, 0, 45, 104, 118, 
	0, 104, 118, 0, 101, 0, 108, 0, 
	112, 0, 0, 101, 0, 114, 0, 115, 
	0, 105, 0, 111, 0, 110, 0, 0, 
	114, 0, 111, 0, 112, 0, 45, 0
};

static const char _params_single_lengths[] = {
	0, 3, 1, 9, 4, 3, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 2, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 2, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 4, 3, 2, 2, 
	2, 1, 2, 2, 2, 2, 2, 2, 
	1, 2, 2, 2, 1, 1
};

static const char _params_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0
};

static const short _params_index_offsets[] = {
	0, 0, 4, 6, 16, 21, 25, 27, 
	29, 31, 33, 35, 37, 39, 41, 43, 
	45, 47, 49, 51, 53, 55, 57, 59, 
	61, 63, 65, 68, 70, 72, 74, 76, 
	78, 80, 82, 84, 86, 88, 90, 92, 
	94, 96, 98, 101, 103, 105, 107, 109, 
	111, 113, 115, 117, 119, 121, 123, 125, 
	127, 129, 131, 133, 135, 137, 139, 141, 
	143, 145, 147, 149, 151, 156, 160, 163, 
	166, 169, 171, 174, 177, 180, 183, 186, 
	189, 191, 194, 197, 200, 202
};

static const char _params_trans_targs[] = {
	0, 68, 81, 2, 85, 2, 4, 29, 
	45, 13, 25, 54, 65, 19, 39, 0, 
	5, 26, 42, 57, 0, 6, 14, 22, 
	0, 7, 0, 8, 0, 9, 0, 10, 
	0, 11, 0, 12, 0, 13, 0, 85, 
	0, 15, 0, 16, 0, 17, 0, 18, 
	0, 19, 0, 20, 0, 0, 21, 85, 
	21, 23, 0, 24, 0, 25, 0, 85, 
	0, 27, 32, 0, 28, 0, 29, 0, 
	30, 0, 0, 31, 85, 31, 33, 0, 
	34, 0, 35, 0, 36, 0, 37, 0, 
	38, 0, 39, 0, 40, 0, 0, 41, 
	85, 41, 43, 48, 0, 44, 0, 45, 
	0, 46, 0, 0, 47, 85, 47, 49, 
	0, 50, 0, 51, 0, 52, 0, 53, 
	0, 54, 0, 55, 0, 0, 56, 85, 
	56, 58, 0, 59, 0, 60, 0, 61, 
	0, 62, 0, 63, 0, 64, 0, 65, 
	0, 66, 0, 0, 67, 85, 67, 85, 
	69, 73, 80, 2, 85, 70, 74, 2, 
	85, 71, 2, 85, 72, 2, 85, 73, 
	2, 85, 2, 85, 75, 2, 85, 76, 
	2, 85, 77, 2, 85, 78, 2, 85, 
	79, 2, 85, 80, 2, 85, 2, 85, 
	82, 2, 85, 83, 2, 85, 84, 2, 
	85, 2, 3, 0, 0
};

static const char _params_trans_actions[] = {
	0, 28, 28, 28, 25, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 3, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 28, 7, 
	1, 0, 0, 0, 0, 0, 0, 5, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 28, 10, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 28, 
	13, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 28, 16, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 28, 19, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 28, 22, 1, 25, 
	1, 1, 1, 1, 25, 1, 1, 1, 
	25, 1, 1, 25, 1, 1, 25, 1, 
	1, 35, 1, 25, 1, 1, 25, 1, 
	1, 25, 1, 1, 25, 1, 1, 25, 
	1, 1, 25, 1, 1, 39, 1, 25, 
	1, 1, 25, 1, 1, 25, 1, 1, 
	31, 1, 0, 0, 0
};

static const int params_start = 1;
static const int params_first_final = 85;
static const int params_error = 0;

static const int params_en_main = 1;


#line 84 "src/usage.rl"

static void params_init(struct params *fsm, options_t* opt)
{
    memset(opt, 0, sizeof(options_t));

    fsm->opt = opt;
    fsm->buflen = 0;
    fsm->opt->db_size = strdup("1000");
    fsm->opt->host = strdup("127.0.0.1");
    fsm->opt->http_port = strdup("8000");
    fsm->opt->path = strdup("store");
    fsm->opt->pid_file = strdup("/var/run/pearl.pid");
    fsm->opt->raft_port = strdup("9000");

    
#line 212 "src/usage.c"
	{
	 fsm->cs = params_start;
	}

#line 99 "src/usage.rl"
}

static void params_execute(struct params *fsm, const char *data, int len)
{
    const char *p = data;
    const char *pe = data + len;

    
#line 226 "src/usage.c"
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
	_keys = _params_trans_keys + _params_key_offsets[ fsm->cs];
	_trans = _params_index_offsets[ fsm->cs];

	_klen = _params_single_lengths[ fsm->cs];
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

	_klen = _params_range_lengths[ fsm->cs];
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
	 fsm->cs = _params_trans_targs[_trans];

	if ( _params_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _params_actions + _params_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 43 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = (*p);
    }
	break;
	case 1:
#line 48 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = 0;
    }
	break;
	case 2:
#line 53 "src/usage.rl"
	{ fsm->buflen = 0; }
	break;
	case 3:
#line 55 "src/usage.rl"
	{ fsm->opt->drop = 1; }
	break;
	case 4:
#line 56 "src/usage.rl"
	{ fsm->opt->daemonize = 1; }
	break;
	case 5:
#line 57 "src/usage.rl"
	{ fsm->opt->debug = 1; }
	break;
	case 6:
#line 58 "src/usage.rl"
	{ fsm->opt->help = 1; }
	break;
	case 7:
#line 59 "src/usage.rl"
	{ fsm->opt->version = 1; }
	break;
	case 8:
#line 60 "src/usage.rl"
	{ fsm->opt->db_size = strdup(fsm->buffer); }
	break;
	case 9:
#line 61 "src/usage.rl"
	{ fsm->opt->host = strdup(fsm->buffer); }
	break;
	case 10:
#line 62 "src/usage.rl"
	{ fsm->opt->http_port = strdup(fsm->buffer); }
	break;
	case 11:
#line 63 "src/usage.rl"
	{ fsm->opt->path = strdup(fsm->buffer); }
	break;
	case 12:
#line 64 "src/usage.rl"
	{ fsm->opt->pid_file = strdup(fsm->buffer); }
	break;
	case 13:
#line 65 "src/usage.rl"
	{ fsm->opt->raft_port = strdup(fsm->buffer); }
	break;
	case 14:
#line 66 "src/usage.rl"
	{ fsm->opt->PEERS = strdup(fsm->buffer); }
	break;
#line 365 "src/usage.c"
		}
	}

_again:
	if (  fsm->cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

#line 107 "src/usage.rl"
}

static int params_finish(struct params *fsm)
{
    if (fsm->cs == params_error)
        return -1;
    if (fsm->cs >= params_first_final)
        return 1;
    return 0;
}

static void show_usage()
{
    fprintf(stdout, "ticketd - a unique ticket server\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "  ticketd PEERS [--daemonize | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE | -g]\n");
    fprintf(stdout, "  ticketd drop [-P DB_PATH]\n");
    fprintf(stdout, "  ticketd --version\n");
    fprintf(stdout, "  ticketd --help\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  -d --daemonize           Run as a daemon.\n");
    fprintf(stdout, "  -P --path DB_PATH        Path where database files will be kept [default: store]\n");
    fprintf(stdout, "  -H --host HOST           Host to listen on [default: 127.0.0.1]\n");
    fprintf(stdout, "  -p --raft_port PORT      Port for Raft peer traffic [default: 9000]\n");
    fprintf(stdout, "  -t --http_port PORT      Port for HTTP traffic [default: 8000]\n");
    fprintf(stdout, "  -s --db_size SIZE        Size of database in megabytes [default: 1000]\n");
    fprintf(stdout, "  -i --pid_file PID_FILE   Pid file [default: /var/run/pearl.pid]\n");
    fprintf(stdout, "  -g --debug               Switch on debugging mode\n");
    fprintf(stdout, "  -v --version             Display version.\n");
    fprintf(stdout, "  -h --help                Prints a short usage summary.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Commands:\n");
    fprintf(stdout, "  drop                     Delete database\n");
    fprintf(stdout, "\n");
}

static int parse_options(int argc, char **argv, options_t* options)
{
    int a;
    struct params params;

    params_init(&params, options);
    for (a = 1; a < argc; a++ )
        params_execute(&params, argv[a], strlen(argv[a]) + 1);
    if (params_finish(&params) != 1)
    {
        fprintf(stderr, "Error processing arguments\n");
        show_usage();
        return -1;
    }

    return 0;
}

