
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


#line 101 "src/usage.rl"



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
	0, 0, 9, 13, 16, 17, 18, 19, 
	20, 21, 22, 23, 24, 31, 34, 35, 
	36, 37, 38, 39, 40, 42, 43, 44, 
	45, 46, 47, 48, 49, 50, 51, 52, 
	53, 54, 55, 56, 57, 58, 59, 60, 
	61, 62, 63, 64, 65, 66, 67, 68, 
	70, 71, 72, 73, 74, 75, 76, 77, 
	78, 79, 80, 81, 82, 83, 84, 86, 
	87, 88, 89, 90, 91, 92, 93, 94, 
	95, 96, 97, 98, 99, 100, 102, 103, 
	104, 105, 106, 107, 116, 120, 123, 124, 
	125, 126, 127, 128, 129, 130, 131, 132, 
	133, 134, 135, 136, 137, 138, 139, 140, 
	141, 142, 143, 145, 146, 147, 148, 149, 
	150, 151, 152, 153, 154, 155, 156, 157, 
	158, 159, 160, 162, 163, 164, 165, 166, 
	167, 168, 169, 170, 171, 172, 173, 174, 
	175, 176, 177, 178, 179, 180, 181, 182, 
	183, 184, 185, 186, 187, 188, 189, 190, 
	194, 195, 195, 196
};

static const char _params_trans_keys[] = {
	45, 72, 80, 100, 103, 104, 105, 115, 
	118, 100, 104, 112, 118, 97, 98, 101, 
	101, 109, 111, 110, 105, 122, 101, 0, 
	45, 72, 80, 100, 103, 105, 115, 100, 
	104, 112, 111, 115, 116, 0, 0, 0, 
	97, 105, 116, 104, 0, 0, 0, 100, 
	95, 102, 105, 108, 101, 0, 0, 0, 
	0, 0, 0, 0, 95, 115, 105, 122, 
	101, 98, 117, 103, 101, 111, 108, 112, 
	0, 101, 114, 115, 105, 111, 110, 0, 
	114, 111, 112, 0, 45, 80, 112, 97, 
	116, 104, 0, 0, 0, 111, 105, 110, 
	0, 0, 0, 45, 45, 73, 105, 100, 
	0, 0, 0, 45, 72, 80, 100, 103, 
	105, 112, 115, 116, 100, 104, 112, 114, 
	97, 98, 101, 101, 109, 111, 110, 105, 
	122, 101, 0, 95, 115, 105, 122, 101, 
	0, 0, 0, 98, 117, 103, 0, 111, 
	116, 115, 116, 0, 0, 0, 116, 112, 
	95, 112, 111, 114, 116, 0, 0, 0, 
	97, 105, 116, 104, 0, 0, 0, 100, 
	95, 102, 105, 108, 101, 0, 0, 0, 
	97, 102, 116, 95, 112, 111, 114, 116, 
	0, 0, 0, 101, 119, 0, 45, 100, 
	106, 110, 45, 45, 45, 0
};

static const char _params_single_lengths[] = {
	0, 9, 4, 3, 1, 1, 1, 1, 
	1, 1, 1, 1, 7, 3, 1, 1, 
	1, 1, 1, 1, 2, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 2, 1, 1, 
	1, 1, 1, 9, 4, 3, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 2, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 2, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 4, 
	1, 0, 1, 1
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
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0
};

static const short _params_index_offsets[] = {
	0, 0, 10, 15, 19, 21, 23, 25, 
	27, 29, 31, 33, 35, 43, 47, 49, 
	51, 53, 55, 57, 59, 62, 64, 66, 
	68, 70, 72, 74, 76, 78, 80, 82, 
	84, 86, 88, 90, 92, 94, 96, 98, 
	100, 102, 104, 106, 108, 110, 112, 114, 
	117, 119, 121, 123, 125, 127, 129, 131, 
	133, 135, 137, 139, 141, 143, 145, 148, 
	150, 152, 154, 156, 158, 160, 162, 164, 
	166, 168, 170, 172, 174, 176, 179, 181, 
	183, 185, 187, 189, 199, 204, 208, 210, 
	212, 214, 216, 218, 220, 222, 224, 226, 
	228, 230, 232, 234, 236, 238, 240, 242, 
	244, 246, 248, 251, 253, 255, 257, 259, 
	261, 263, 265, 267, 269, 271, 273, 275, 
	277, 279, 281, 284, 286, 288, 290, 292, 
	294, 296, 298, 300, 302, 304, 306, 308, 
	310, 312, 314, 316, 318, 320, 322, 324, 
	326, 328, 330, 332, 334, 336, 338, 340, 
	345, 347, 348, 350
};

static const unsigned char _params_trans_targs[] = {
	2, 17, 23, 11, 35, 50, 32, 36, 
	57, 0, 3, 47, 20, 51, 0, 4, 
	39, 44, 0, 5, 0, 6, 0, 7, 
	0, 8, 0, 9, 0, 10, 0, 11, 
	0, 152, 0, 13, 17, 23, 11, 35, 
	32, 36, 0, 3, 14, 20, 0, 15, 
	0, 16, 0, 17, 0, 18, 0, 0, 
	19, 152, 19, 21, 26, 0, 22, 0, 
	23, 0, 24, 0, 0, 25, 152, 25, 
	27, 0, 28, 0, 29, 0, 30, 0, 
	31, 0, 32, 0, 33, 0, 0, 34, 
	152, 34, 152, 0, 37, 0, 0, 38, 
	152, 38, 40, 0, 41, 0, 42, 0, 
	43, 0, 36, 0, 45, 0, 46, 0, 
	35, 0, 48, 15, 0, 49, 0, 50, 
	0, 153, 0, 52, 0, 53, 0, 54, 
	0, 55, 0, 56, 0, 57, 0, 153, 
	0, 59, 0, 60, 0, 61, 0, 154, 
	0, 63, 67, 0, 64, 0, 65, 0, 
	66, 0, 67, 0, 68, 0, 0, 69, 
	154, 69, 71, 0, 72, 0, 73, 0, 
	74, 0, 0, 75, 76, 75, 77, 0, 
	78, 80, 0, 79, 0, 80, 0, 81, 
	0, 0, 82, 155, 82, 84, 109, 125, 
	93, 105, 134, 145, 99, 119, 0, 85, 
	106, 122, 137, 0, 86, 94, 102, 0, 
	87, 0, 88, 0, 89, 0, 90, 0, 
	91, 0, 92, 0, 93, 0, 155, 0, 
	95, 0, 96, 0, 97, 0, 98, 0, 
	99, 0, 100, 0, 0, 101, 155, 101, 
	103, 0, 104, 0, 105, 0, 155, 0, 
	107, 112, 0, 108, 0, 109, 0, 110, 
	0, 0, 111, 155, 111, 113, 0, 114, 
	0, 115, 0, 116, 0, 117, 0, 118, 
	0, 119, 0, 120, 0, 0, 121, 155, 
	121, 123, 128, 0, 124, 0, 125, 0, 
	126, 0, 0, 127, 155, 127, 129, 0, 
	130, 0, 131, 0, 132, 0, 133, 0, 
	134, 0, 135, 0, 0, 136, 155, 136, 
	138, 0, 139, 0, 140, 0, 141, 0, 
	142, 0, 143, 0, 144, 0, 145, 0, 
	146, 0, 0, 147, 155, 147, 149, 0, 
	150, 0, 76, 0, 1, 58, 70, 148, 
	0, 12, 0, 0, 62, 0, 83, 0, 
	0
};

static const char _params_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 9, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	41, 20, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 41, 29, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 41, 
	32, 1, 11, 0, 0, 0, 0, 41, 
	17, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 13, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 15, 
	0, 0, 0, 0, 0, 0, 0, 3, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 41, 
	29, 1, 0, 0, 0, 0, 0, 0, 
	5, 0, 0, 41, 38, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 41, 26, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 9, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 41, 17, 1, 
	0, 0, 0, 0, 0, 0, 11, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 41, 20, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 41, 23, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 41, 29, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 41, 32, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 41, 35, 1, 0, 0, 
	0, 0, 7, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0
};

static const int params_start = 151;
static const int params_first_final = 151;
static const int params_error = 0;

static const int params_en_main = 151;


#line 104 "src/usage.rl"

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

    
#line 299 "src/usage.c"
	{
	 fsm->cs = params_start;
	}

#line 119 "src/usage.rl"
}

static void params_execute(struct params *fsm, const char *data, int len)
{
    const char *p = data;
    const char *pe = data + len;

    
#line 313 "src/usage.c"
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
#line 464 "src/usage.c"
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

#line 127 "src/usage.rl"
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
    fprintf(stdout, "  ticketd [-d | -P DB_PATH | -H HOST | -s SIZE | -i PID_FILE | -g]\n");
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

