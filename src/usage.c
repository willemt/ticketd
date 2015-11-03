
#line 1 "src/usage.rl"
#include <stdio.h>
#include <string.h>

#define BUFLEN 1024
#define BUFSIZE 2048

typedef struct
{
    /* commands */
    int drop;
    int join;
    int new;

    /* flags */
    int daemonize;
    int debug;
    int help;
    int version;

    /* options */
    char* db_size;
    char* host;
    char* http_port;
    char* id;
    char* path;
    char* pid_file;
    char* raft_port;

    /* arguments */
    char* PEER;

} options_t;

struct params
{
    options_t* opt;
    char buffer[BUFLEN + 1];
    int buflen;
    int cs;
};


#line 103 "src/usage.rl"



#line 50 "src/usage.c"
static const char _params_actions[] = {
	0, 1, 0, 1, 3, 1, 4, 1, 
	5, 1, 6, 1, 7, 1, 8, 1, 
	9, 2, 1, 10, 2, 1, 11, 2, 
	1, 12, 2, 1, 13, 2, 1, 14, 
	2, 1, 15, 2, 1, 16, 2, 1, 
	17, 2, 2, 0
};

static const unsigned char _params_key_offsets[] = {
	0, 0, 11, 16, 19, 20, 21, 22, 
	23, 24, 25, 26, 27, 36, 40, 42, 
	43, 44, 45, 46, 47, 48, 49, 50, 
	51, 52, 53, 54, 55, 56, 57, 59, 
	60, 61, 62, 63, 64, 65, 66, 67, 
	68, 69, 70, 71, 72, 73, 74, 75, 
	76, 77, 78, 79, 80, 81, 82, 83, 
	84, 85, 86, 87, 88, 89, 90, 91, 
	92, 93, 94, 95, 96, 99, 100, 101, 
	102, 103, 104, 105, 106, 107, 108, 109, 
	110, 111, 112, 113, 115, 116, 117, 118, 
	119, 120, 121, 122, 123, 124, 125, 126, 
	127, 128, 129, 131, 132, 133, 134, 135, 
	136, 137, 138, 139, 143, 144, 144
};

static const char _params_trans_keys[] = {
	45, 72, 80, 100, 103, 104, 105, 112, 
	115, 116, 118, 100, 104, 112, 114, 118, 
	97, 98, 101, 101, 109, 111, 110, 105, 
	122, 101, 0, 45, 72, 80, 100, 103, 
	105, 112, 115, 116, 100, 104, 112, 114, 
	111, 116, 115, 116, 0, 0, 0, 116, 
	112, 95, 112, 111, 114, 116, 0, 0, 
	0, 97, 105, 116, 104, 0, 0, 0, 
	100, 95, 102, 105, 108, 101, 0, 0, 
	0, 97, 102, 116, 95, 112, 111, 114, 
	116, 0, 0, 0, 0, 0, 0, 0, 
	95, 115, 105, 122, 101, 98, 117, 103, 
	101, 111, 116, 108, 112, 0, 101, 114, 
	115, 105, 111, 110, 0, 114, 111, 112, 
	0, 45, 80, 112, 97, 116, 104, 0, 
	0, 0, 111, 105, 110, 0, 0, 0, 
	45, 45, 73, 105, 100, 0, 0, 0, 
	101, 119, 0, 45, 100, 106, 110, 45, 
	45, 0
};

static const char _params_single_lengths[] = {
	0, 11, 5, 3, 1, 1, 1, 1, 
	1, 1, 1, 1, 9, 4, 2, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 3, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 2, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 2, 1, 1, 1, 1, 1, 
	1, 1, 1, 4, 1, 0, 1
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
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0
};

static const short _params_index_offsets[] = {
	0, 0, 12, 18, 22, 24, 26, 28, 
	30, 32, 34, 36, 38, 48, 53, 56, 
	58, 60, 62, 64, 66, 68, 70, 72, 
	74, 76, 78, 80, 82, 84, 86, 89, 
	91, 93, 95, 97, 99, 101, 103, 105, 
	107, 109, 111, 113, 115, 117, 119, 121, 
	123, 125, 127, 129, 131, 133, 135, 137, 
	139, 141, 143, 145, 147, 149, 151, 153, 
	155, 157, 159, 161, 163, 167, 169, 171, 
	173, 175, 177, 179, 181, 183, 185, 187, 
	189, 191, 193, 195, 198, 200, 202, 204, 
	206, 208, 210, 212, 214, 216, 218, 220, 
	222, 224, 226, 229, 231, 233, 235, 237, 
	239, 241, 243, 245, 250, 252, 253
};

static const char _params_trans_targs[] = {
	2, 17, 33, 11, 56, 71, 42, 53, 
	57, 27, 78, 0, 3, 68, 30, 45, 
	72, 0, 4, 60, 65, 0, 5, 0, 
	6, 0, 7, 0, 8, 0, 9, 0, 
	10, 0, 11, 0, 108, 0, 13, 17, 
	33, 11, 56, 42, 53, 57, 27, 0, 
	3, 14, 30, 45, 0, 15, 20, 0, 
	16, 0, 17, 0, 18, 0, 0, 19, 
	108, 19, 21, 0, 22, 0, 23, 0, 
	24, 0, 25, 0, 26, 0, 27, 0, 
	28, 0, 0, 29, 108, 29, 31, 36, 
	0, 32, 0, 33, 0, 34, 0, 0, 
	35, 108, 35, 37, 0, 38, 0, 39, 
	0, 40, 0, 41, 0, 42, 0, 43, 
	0, 0, 44, 108, 44, 46, 0, 47, 
	0, 48, 0, 49, 0, 50, 0, 51, 
	0, 52, 0, 53, 0, 54, 0, 0, 
	55, 108, 55, 108, 0, 58, 0, 0, 
	59, 108, 59, 61, 0, 62, 0, 63, 
	0, 64, 0, 57, 0, 66, 0, 67, 
	0, 56, 0, 69, 15, 20, 0, 70, 
	0, 71, 0, 109, 0, 73, 0, 74, 
	0, 75, 0, 76, 0, 77, 0, 78, 
	0, 109, 0, 80, 0, 81, 0, 82, 
	0, 110, 0, 84, 88, 0, 85, 0, 
	86, 0, 87, 0, 88, 0, 89, 0, 
	0, 90, 110, 90, 92, 0, 93, 0, 
	94, 0, 95, 0, 0, 96, 97, 96, 
	98, 0, 99, 101, 0, 100, 0, 101, 
	0, 102, 0, 0, 103, 108, 103, 105, 
	0, 106, 0, 97, 0, 1, 79, 91, 
	104, 0, 12, 0, 0, 83, 0, 0
};

static const char _params_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 9, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 41, 
	20, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 41, 23, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	41, 29, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 41, 32, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	41, 35, 1, 11, 0, 0, 0, 0, 
	41, 17, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 13, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 15, 0, 0, 0, 0, 0, 0, 
	0, 3, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 41, 29, 1, 0, 0, 0, 0, 
	0, 0, 5, 0, 0, 41, 38, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 41, 26, 1, 0, 
	0, 0, 0, 7, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0
};

static const int params_start = 107;
static const int params_first_final = 107;
static const int params_error = 0;

static const int params_en_main = 107;


#line 106 "src/usage.rl"

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

    
#line 243 "src/usage.c"
	{
	 fsm->cs = params_start;
	}

#line 121 "src/usage.rl"
}

static void params_execute(struct params *fsm, const char *data, int len)
{
    const char *p = data;
    const char *pe = data + len;

    
#line 257 "src/usage.c"
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
#line 46 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = (*p);
    }
	break;
	case 1:
#line 51 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = 0;
    }
	break;
	case 2:
#line 56 "src/usage.rl"
	{ fsm->buflen = 0; }
	break;
	case 3:
#line 58 "src/usage.rl"
	{ fsm->opt->drop = 1; }
	break;
	case 4:
#line 59 "src/usage.rl"
	{ fsm->opt->join = 1; }
	break;
	case 5:
#line 60 "src/usage.rl"
	{ fsm->opt->new = 1; }
	break;
	case 6:
#line 61 "src/usage.rl"
	{ fsm->opt->daemonize = 1; }
	break;
	case 7:
#line 62 "src/usage.rl"
	{ fsm->opt->debug = 1; }
	break;
	case 8:
#line 63 "src/usage.rl"
	{ fsm->opt->help = 1; }
	break;
	case 9:
#line 64 "src/usage.rl"
	{ fsm->opt->version = 1; }
	break;
	case 10:
#line 65 "src/usage.rl"
	{ fsm->opt->db_size = strdup(fsm->buffer); }
	break;
	case 11:
#line 66 "src/usage.rl"
	{ fsm->opt->host = strdup(fsm->buffer); }
	break;
	case 12:
#line 67 "src/usage.rl"
	{ fsm->opt->http_port = strdup(fsm->buffer); }
	break;
	case 13:
#line 68 "src/usage.rl"
	{ fsm->opt->id = strdup(fsm->buffer); }
	break;
	case 14:
#line 69 "src/usage.rl"
	{ fsm->opt->path = strdup(fsm->buffer); }
	break;
	case 15:
#line 70 "src/usage.rl"
	{ fsm->opt->pid_file = strdup(fsm->buffer); }
	break;
	case 16:
#line 71 "src/usage.rl"
	{ fsm->opt->raft_port = strdup(fsm->buffer); }
	break;
	case 17:
#line 72 "src/usage.rl"
	{ fsm->opt->PEER = strdup(fsm->buffer); }
	break;
#line 408 "src/usage.c"
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

#line 129 "src/usage.rl"
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
    fprintf(stdout, "  ticketd [-d | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE | -g]\n");
    fprintf(stdout, "  ticketd new --id ID [-d | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE | -g]\n");
    fprintf(stdout, "  ticketd join PEER --id ID [-d | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE | -g]\n");
    fprintf(stdout, "  ticketd drop [-P DB_PATH]\n");
    fprintf(stdout, "  ticketd --version\n");
    fprintf(stdout, "  ticketd --help\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  -d --daemonize           Run as a daemon.\n");
    fprintf(stdout, "  -I --id ID               This server's manually set Raft ID\n");
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
    fprintf(stdout, "  new                      Destroy database and create a new cluster\n");
    fprintf(stdout, "  join                     Destroy database and join cluster via peer\n");
    fprintf(stdout, "  drop                     Destroy database\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Without a command, ticketd will reload its database and rejoin the cluster.\n");
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

