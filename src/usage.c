
#line 1 "src/usage.rl"
#include <stdio.h>
#include <string.h>

#define BUFLEN 1024
#define BUFSIZE 2048

typedef struct
{
    /* commands */
    

    /* flags */
    int daemonize;
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


#line 77 "src/usage.rl"



#line 46 "src/usage.c"
static const char _params_actions[] = {
	0, 1, 0, 1, 3, 2, 1, 6, 
	2, 1, 7, 2, 1, 8, 2, 1, 
	9, 2, 1, 10, 2, 1, 11, 2, 
	1, 12, 2, 2, 0, 3, 1, 12, 
	4, 3, 1, 12, 5
};

static const char _params_key_offsets[] = {
	0, 0, 2, 3, 11, 15, 17, 18, 
	19, 20, 21, 22, 23, 24, 25, 26, 
	27, 28, 29, 30, 31, 32, 33, 35, 
	36, 37, 38, 39, 40, 41, 42, 43, 
	44, 45, 46, 47, 48, 49, 50, 52, 
	53, 54, 55, 56, 57, 58, 59, 60, 
	61, 62, 63, 64, 65, 66, 67, 68, 
	69, 70, 71, 72, 73, 74, 75, 76, 
	77, 81, 84, 86, 88, 90, 91, 93, 
	95, 97, 99, 101, 103, 104
};

static const char _params_trans_keys[] = {
	0, 45, 0, 45, 72, 80, 100, 105, 
	112, 115, 116, 100, 104, 112, 114, 97, 
	98, 101, 109, 111, 110, 105, 122, 101, 
	0, 95, 115, 105, 122, 101, 0, 0, 
	0, 111, 116, 115, 116, 0, 0, 0, 
	116, 112, 95, 112, 111, 114, 116, 0, 
	0, 0, 97, 105, 116, 104, 0, 0, 
	0, 100, 95, 102, 105, 108, 101, 0, 
	0, 0, 97, 102, 116, 95, 112, 111, 
	114, 116, 0, 0, 0, 0, 45, 104, 
	118, 0, 104, 118, 0, 101, 0, 108, 
	0, 112, 0, 0, 101, 0, 114, 0, 
	115, 0, 105, 0, 111, 0, 110, 0, 
	45, 0
};

static const char _params_single_lengths[] = {
	0, 2, 1, 8, 4, 2, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	4, 3, 2, 2, 2, 1, 2, 2, 
	2, 2, 2, 2, 1, 1
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
	0, 0, 0, 0, 0, 0
};

static const short _params_index_offsets[] = {
	0, 0, 3, 5, 14, 19, 22, 24, 
	26, 28, 30, 32, 34, 36, 38, 40, 
	42, 44, 46, 48, 50, 52, 54, 57, 
	59, 61, 63, 65, 67, 69, 71, 73, 
	75, 77, 79, 81, 83, 85, 87, 90, 
	92, 94, 96, 98, 100, 102, 104, 106, 
	108, 110, 112, 114, 116, 118, 120, 122, 
	124, 126, 128, 130, 132, 134, 136, 138, 
	140, 145, 149, 152, 155, 158, 160, 163, 
	166, 169, 172, 175, 178, 180
};

static const char _params_trans_targs[] = {
	0, 64, 2, 77, 2, 4, 25, 41, 
	13, 50, 61, 19, 35, 0, 5, 22, 
	38, 53, 0, 6, 14, 0, 7, 0, 
	8, 0, 9, 0, 10, 0, 11, 0, 
	12, 0, 13, 0, 77, 0, 15, 0, 
	16, 0, 17, 0, 18, 0, 19, 0, 
	20, 0, 0, 21, 77, 21, 23, 28, 
	0, 24, 0, 25, 0, 26, 0, 0, 
	27, 77, 27, 29, 0, 30, 0, 31, 
	0, 32, 0, 33, 0, 34, 0, 35, 
	0, 36, 0, 0, 37, 77, 37, 39, 
	44, 0, 40, 0, 41, 0, 42, 0, 
	0, 43, 77, 43, 45, 0, 46, 0, 
	47, 0, 48, 0, 49, 0, 50, 0, 
	51, 0, 0, 52, 77, 52, 54, 0, 
	55, 0, 56, 0, 57, 0, 58, 0, 
	59, 0, 60, 0, 61, 0, 62, 0, 
	0, 63, 77, 63, 77, 65, 69, 76, 
	2, 77, 66, 70, 2, 77, 67, 2, 
	77, 68, 2, 77, 69, 2, 77, 2, 
	77, 71, 2, 77, 72, 2, 77, 73, 
	2, 77, 74, 2, 77, 75, 2, 77, 
	76, 2, 77, 2, 3, 0, 0
};

static const char _params_trans_actions[] = {
	0, 26, 26, 23, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 3, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 26, 5, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	26, 8, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 26, 11, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 26, 14, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 26, 17, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 26, 20, 1, 23, 1, 1, 1, 
	1, 23, 1, 1, 1, 23, 1, 1, 
	23, 1, 1, 23, 1, 1, 29, 1, 
	23, 1, 1, 23, 1, 1, 23, 1, 
	1, 23, 1, 1, 23, 1, 1, 23, 
	1, 1, 33, 1, 0, 0, 0
};

static const int params_start = 1;
static const int params_first_final = 77;
static const int params_error = 0;

static const int params_en_main = 1;


#line 80 "src/usage.rl"

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

    
#line 199 "src/usage.c"
	{
	 fsm->cs = params_start;
	}

#line 95 "src/usage.rl"
}

static void params_execute(struct params *fsm, const char *data, int len)
{
    const char *p = data;
    const char *pe = data + len;

    
#line 213 "src/usage.c"
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
#line 42 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = (*p);
    }
	break;
	case 1:
#line 47 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = 0;
    }
	break;
	case 2:
#line 52 "src/usage.rl"
	{ fsm->buflen = 0; }
	break;
	case 3:
#line 55 "src/usage.rl"
	{ fsm->opt->daemonize = 1; }
	break;
	case 4:
#line 56 "src/usage.rl"
	{ fsm->opt->help = 1; }
	break;
	case 5:
#line 57 "src/usage.rl"
	{ fsm->opt->version = 1; }
	break;
	case 6:
#line 58 "src/usage.rl"
	{ fsm->opt->db_size = strdup(fsm->buffer); }
	break;
	case 7:
#line 59 "src/usage.rl"
	{ fsm->opt->host = strdup(fsm->buffer); }
	break;
	case 8:
#line 60 "src/usage.rl"
	{ fsm->opt->http_port = strdup(fsm->buffer); }
	break;
	case 9:
#line 61 "src/usage.rl"
	{ fsm->opt->path = strdup(fsm->buffer); }
	break;
	case 10:
#line 62 "src/usage.rl"
	{ fsm->opt->pid_file = strdup(fsm->buffer); }
	break;
	case 11:
#line 63 "src/usage.rl"
	{ fsm->opt->raft_port = strdup(fsm->buffer); }
	break;
	case 12:
#line 64 "src/usage.rl"
	{ fsm->opt->PEERS = strdup(fsm->buffer); }
	break;
#line 344 "src/usage.c"
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

#line 103 "src/usage.rl"
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
    fprintf(stdout, "kippud - a unique ticket server\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "  kippud PEERS [--daemonize | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE]\n");
    fprintf(stdout, "  kippud --version\n");
    fprintf(stdout, "  kippud --help\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  -d --daemonize           Run as a daemon.\n");
    fprintf(stdout, "  -P --path DB_PATH        Path where database files will be kept [default: store]\n");
    fprintf(stdout, "  -H --host HOST           Host to listen on [default: 127.0.0.1]\n");
    fprintf(stdout, "  -p --raft_port PORT      Port for Raft peer traffic [default: 9000]\n");
    fprintf(stdout, "  -t --http_port PORT      Port for HTTP traffic [default: 8000]\n");
    fprintf(stdout, "  -s --db_size SIZE        Size of database in megabytes [default: 1000]\n");
    fprintf(stdout, "  -i --pid_file PID_FILE   Pid file [default: /var/run/pearl.pid]\n");
    fprintf(stdout, "  -v --version             Display version.\n");
    fprintf(stdout, "  -h --help                Prints a short usage summary.\n");
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

