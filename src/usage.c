
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
    int leave;
    int start;

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


#line 106 "src/usage.rl"



#line 51 "src/usage.c"
static const char _params_actions[] = {
	0, 1, 0, 1, 3, 1, 4, 1, 
	5, 1, 6, 1, 7, 1, 8, 1, 
	9, 1, 10, 2, 1, 11, 2, 1, 
	12, 2, 1, 13, 2, 1, 14, 2, 
	1, 15, 2, 1, 16, 2, 1, 17, 
	2, 1, 18, 2, 2, 0
};

static const unsigned char _params_key_offsets[] = {
	0, 0, 9, 13, 16, 17, 18, 19, 
	20, 21, 22, 23, 24, 31, 34, 35, 
	36, 37, 38, 39, 40, 42, 43, 44, 
	45, 46, 47, 48, 49, 50, 51, 52, 
	53, 54, 55, 56, 57, 58, 59, 60, 
	61, 62, 63, 64, 65, 66, 67, 68, 
	70, 71, 72, 73, 74, 75, 76, 77, 
	78, 79, 80, 81, 82, 83, 84, 87, 
	89, 90, 91, 92, 93, 94, 95, 96, 
	97, 98, 99, 100, 101, 102, 103, 104, 
	105, 106, 107, 109, 110, 111, 112, 113, 
	114, 123, 127, 130, 131, 132, 133, 134, 
	135, 136, 137, 138, 139, 140, 141, 142, 
	143, 144, 145, 146, 147, 148, 149, 150, 
	152, 153, 154, 155, 156, 157, 158, 159, 
	160, 161, 162, 163, 164, 165, 166, 167, 
	169, 170, 171, 172, 173, 174, 175, 176, 
	177, 178, 179, 180, 181, 182, 183, 184, 
	185, 186, 187, 188, 189, 190, 191, 192, 
	193, 194, 195, 196, 197, 198, 199, 200, 
	201, 202, 203, 204, 209, 210, 210, 211
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
	114, 111, 112, 0, 45, 80, 103, 100, 
	112, 101, 98, 117, 103, 0, 97, 116, 
	104, 0, 0, 0, 111, 105, 110, 0, 
	0, 0, 45, 45, 73, 105, 100, 0, 
	0, 0, 45, 72, 80, 100, 103, 105, 
	112, 115, 116, 100, 104, 112, 114, 97, 
	98, 101, 101, 109, 111, 110, 105, 122, 
	101, 0, 95, 115, 105, 122, 101, 0, 
	0, 0, 98, 117, 103, 0, 111, 116, 
	115, 116, 0, 0, 0, 116, 112, 95, 
	112, 111, 114, 116, 0, 0, 0, 97, 
	105, 116, 104, 0, 0, 0, 100, 95, 
	102, 105, 108, 101, 0, 0, 0, 97, 
	102, 116, 95, 112, 111, 114, 116, 0, 
	0, 0, 101, 97, 118, 101, 0, 116, 
	97, 114, 116, 0, 45, 100, 106, 108, 
	115, 45, 45, 45, 0
};

static const char _params_single_lengths[] = {
	0, 9, 4, 3, 1, 1, 1, 1, 
	1, 1, 1, 1, 7, 3, 1, 1, 
	1, 1, 1, 1, 2, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 3, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 2, 1, 1, 1, 1, 1, 
	9, 4, 3, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 5, 1, 0, 1, 1
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
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0
};

static const short _params_index_offsets[] = {
	0, 0, 10, 15, 19, 21, 23, 25, 
	27, 29, 31, 33, 35, 43, 47, 49, 
	51, 53, 55, 57, 59, 62, 64, 66, 
	68, 70, 72, 74, 76, 78, 80, 82, 
	84, 86, 88, 90, 92, 94, 96, 98, 
	100, 102, 104, 106, 108, 110, 112, 114, 
	117, 119, 121, 123, 125, 127, 129, 131, 
	133, 135, 137, 139, 141, 143, 145, 149, 
	152, 154, 156, 158, 160, 162, 164, 166, 
	168, 170, 172, 174, 176, 178, 180, 182, 
	184, 186, 188, 191, 193, 195, 197, 199, 
	201, 211, 216, 220, 222, 224, 226, 228, 
	230, 232, 234, 236, 238, 240, 242, 244, 
	246, 248, 250, 252, 254, 256, 258, 260, 
	263, 265, 267, 269, 271, 273, 275, 277, 
	279, 281, 283, 285, 287, 289, 291, 293, 
	296, 298, 300, 302, 304, 306, 308, 310, 
	312, 314, 316, 318, 320, 322, 324, 326, 
	328, 330, 332, 334, 336, 338, 340, 342, 
	344, 346, 348, 350, 352, 354, 356, 358, 
	360, 362, 364, 366, 372, 374, 375, 377
};

static const unsigned char _params_trans_targs[] = {
	2, 17, 23, 11, 35, 50, 32, 36, 
	57, 0, 3, 47, 20, 51, 0, 4, 
	39, 44, 0, 5, 0, 6, 0, 7, 
	0, 8, 0, 9, 0, 10, 0, 11, 
	0, 164, 0, 13, 17, 23, 11, 35, 
	32, 36, 0, 3, 14, 20, 0, 15, 
	0, 16, 0, 17, 0, 18, 0, 0, 
	19, 164, 19, 21, 26, 0, 22, 0, 
	23, 0, 24, 0, 0, 25, 164, 25, 
	27, 0, 28, 0, 29, 0, 30, 0, 
	31, 0, 32, 0, 33, 0, 0, 34, 
	164, 34, 164, 0, 37, 0, 0, 38, 
	164, 38, 40, 0, 41, 0, 42, 0, 
	43, 0, 36, 0, 45, 0, 46, 0, 
	35, 0, 48, 15, 0, 49, 0, 50, 
	0, 165, 0, 52, 0, 53, 0, 54, 
	0, 55, 0, 56, 0, 57, 0, 165, 
	0, 59, 0, 60, 0, 61, 0, 166, 
	0, 63, 72, 68, 0, 64, 69, 0, 
	65, 0, 66, 0, 67, 0, 68, 0, 
	166, 0, 70, 0, 71, 0, 72, 0, 
	73, 0, 0, 74, 166, 74, 76, 0, 
	77, 0, 78, 0, 79, 0, 0, 80, 
	81, 80, 82, 0, 83, 85, 0, 84, 
	0, 85, 0, 86, 0, 0, 87, 167, 
	87, 89, 114, 130, 98, 110, 139, 150, 
	104, 124, 0, 90, 111, 127, 142, 0, 
	91, 99, 107, 0, 92, 0, 93, 0, 
	94, 0, 95, 0, 96, 0, 97, 0, 
	98, 0, 167, 0, 100, 0, 101, 0, 
	102, 0, 103, 0, 104, 0, 105, 0, 
	0, 106, 167, 106, 108, 0, 109, 0, 
	110, 0, 167, 0, 112, 117, 0, 113, 
	0, 114, 0, 115, 0, 0, 116, 167, 
	116, 118, 0, 119, 0, 120, 0, 121, 
	0, 122, 0, 123, 0, 124, 0, 125, 
	0, 0, 126, 167, 126, 128, 133, 0, 
	129, 0, 130, 0, 131, 0, 0, 132, 
	167, 132, 134, 0, 135, 0, 136, 0, 
	137, 0, 138, 0, 139, 0, 140, 0, 
	0, 141, 167, 141, 143, 0, 144, 0, 
	145, 0, 146, 0, 147, 0, 148, 0, 
	149, 0, 150, 0, 151, 0, 0, 152, 
	167, 152, 154, 0, 155, 0, 156, 0, 
	157, 0, 166, 0, 159, 0, 160, 0, 
	161, 0, 162, 0, 81, 0, 1, 58, 
	75, 153, 158, 0, 12, 0, 0, 62, 
	0, 88, 0, 0
};

static const char _params_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 11, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	43, 22, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 43, 31, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 43, 
	34, 1, 13, 0, 0, 0, 0, 43, 
	19, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 15, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 17, 
	0, 0, 0, 0, 0, 0, 0, 3, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	13, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 43, 31, 1, 0, 0, 
	0, 0, 0, 0, 5, 0, 0, 43, 
	40, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 43, 28, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 11, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 43, 19, 1, 0, 0, 0, 0, 
	0, 0, 13, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 43, 22, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 43, 25, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 43, 
	31, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 43, 34, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 43, 
	37, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 7, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 9, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0
};

static const int params_start = 163;
static const int params_first_final = 163;
static const int params_error = 0;

static const int params_en_main = 163;


#line 109 "src/usage.rl"

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

    
#line 312 "src/usage.c"
	{
	 fsm->cs = params_start;
	}

#line 124 "src/usage.rl"
}

static void params_execute(struct params *fsm, const char *data, int len)
{
    const char *p = data;
    const char *pe = data + len;

    
#line 326 "src/usage.c"
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
#line 47 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = (*p);
    }
	break;
	case 1:
#line 52 "src/usage.rl"
	{
        if (fsm->buflen < BUFLEN)
            fsm->buffer[fsm->buflen++] = 0;
    }
	break;
	case 2:
#line 57 "src/usage.rl"
	{ fsm->buflen = 0; }
	break;
	case 3:
#line 59 "src/usage.rl"
	{ fsm->opt->drop = 1; }
	break;
	case 4:
#line 60 "src/usage.rl"
	{ fsm->opt->join = 1; }
	break;
	case 5:
#line 61 "src/usage.rl"
	{ fsm->opt->leave = 1; }
	break;
	case 6:
#line 62 "src/usage.rl"
	{ fsm->opt->start = 1; }
	break;
	case 7:
#line 63 "src/usage.rl"
	{ fsm->opt->daemonize = 1; }
	break;
	case 8:
#line 64 "src/usage.rl"
	{ fsm->opt->debug = 1; }
	break;
	case 9:
#line 65 "src/usage.rl"
	{ fsm->opt->help = 1; }
	break;
	case 10:
#line 66 "src/usage.rl"
	{ fsm->opt->version = 1; }
	break;
	case 11:
#line 67 "src/usage.rl"
	{ fsm->opt->db_size = strdup(fsm->buffer); }
	break;
	case 12:
#line 68 "src/usage.rl"
	{ fsm->opt->host = strdup(fsm->buffer); }
	break;
	case 13:
#line 69 "src/usage.rl"
	{ fsm->opt->http_port = strdup(fsm->buffer); }
	break;
	case 14:
#line 70 "src/usage.rl"
	{ fsm->opt->id = strdup(fsm->buffer); }
	break;
	case 15:
#line 71 "src/usage.rl"
	{ fsm->opt->path = strdup(fsm->buffer); }
	break;
	case 16:
#line 72 "src/usage.rl"
	{ fsm->opt->pid_file = strdup(fsm->buffer); }
	break;
	case 17:
#line 73 "src/usage.rl"
	{ fsm->opt->raft_port = strdup(fsm->buffer); }
	break;
	case 18:
#line 74 "src/usage.rl"
	{ fsm->opt->PEER = strdup(fsm->buffer); }
	break;
#line 481 "src/usage.c"
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

#line 132 "src/usage.rl"
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
    fprintf(stdout, "  ticketd start --id ID [-d | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE | -g]\n");
    fprintf(stdout, "  ticketd join PEER --id ID [-d | -P DB_PATH | -H HOST | -p PORT | -t PORT | -s SIZE | -i PID_FILE | -g]\n");
    fprintf(stdout, "  ticketd leave [-P DB_PATH | -g]\n");
    fprintf(stdout, "  ticketd drop [-P DB_PATH | -g]\n");
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
    fprintf(stdout, "  start                    Destroy database and create a new cluster\n");
    fprintf(stdout, "  join                     Destroy database and join cluster via peer\n");
    fprintf(stdout, "  leave                    Destroy database and leave cluster\n");
    fprintf(stdout, "  drop                     Destroy database\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Without a command, ticketd will rejoin the cluster.\n");
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

