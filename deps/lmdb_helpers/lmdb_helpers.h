#ifndef LMDB_HELPERS_H
#define LMDB_HELPERS_H

#define mdb_fatal(e) { \
        assert(0 != e); \
        fprintf(stderr, "%s:%d - err:%d: %s\n", \
                __FILE__, __LINE__, e, mdb_strerror((e))); \
        exit(1); }

void mdb_db_create(MDB_dbi *dbi, MDB_env *env, const char* db_name);

void mdb_db_env_create(
        MDB_env **env,
	unsigned int flags,
        const char* path,
        int size_mb);
	
void mdb_print_db_stats(MDB_dbi dbi, MDB_env *env);

size_t mdb_env_get_mapsize(MDB_env *env);

void mdb_gets(MDB_env *env, MDB_dbi dbi, char* keystr, MDB_val* val);

int mdb_gets_int(MDB_env *env, MDB_dbi dbi, char* keystr, int *out);

int mdb_puts_int(MDB_txn *txn, MDB_dbi dbi, char* keystr, int in);

int mdb_puts_int_commit(MDB_env *env, MDB_dbi dbi, char* keystr, int in);

/**
 * Delete the first item */
int mdb_poll(MDB_env *env, MDB_dbi dbi, MDB_val *k, MDB_val *v);

/**
 * Delete the last item */
int mdb_pop(MDB_env *env, MDB_dbi dbi, MDB_val *k, MDB_val *v);

void mdb_drop_dbs(MDB_env *env, MDB_dbi dbs[], size_t ndbs);

#endif /* LMDB_HELPERS_H */
