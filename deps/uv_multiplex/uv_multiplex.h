#ifndef UV_MULTIPLEX_H
#define UV_MULTIPLEX_H

#ifndef fatal
#define fatal(e) { \
        assert(0 != e); \
        if (EMFILE == -e) \
            fprintf(stderr, UV_MULTIPLEX_INCREASE_LIMITS); \
        fprintf(stderr, "%s:%d - %s: %s\n", \
                __FILE__, \
                __LINE__, \
                uv_err_name((e)), \
                uv_strerror((e))); \
        exit(1); }
#endif

#define UV_MULTIPLEX_INCREASE_LIMITS \
    "Sorry, please consider increasing file limits\n" \
    "There aren't enough file descriptors available.\n" \
    "\n" \
    "Try this:\n" \
    "\n" \
    "Check current limit:\n" \
    "\tulimit -n\n\n" \
    "Set new limit:\n" \
    "\tulimit -n X\n\n"

typedef struct uv_multiplex_worker_s uv_multiplex_worker_t;

typedef struct
{
    const char* pipe_name;

    uv_pipe_t pipe;

    uv_tcp_t *listener;

    uv_multiplex_worker_t* workers;

    /* number of workers */
    int nworkers;

    /* number of workers that have connected */
    int nconnected;

    void (*worker_start)(void* uv_tcp);

    uv_mutex_t lock;
} uv_multiplex_t;

struct uv_multiplex_worker_s
{
    uv_multiplex_t* m;

    uv_loop_t loop;

    uv_tcp_t listener;

    uv_sem_t sem;

    uv_pipe_t pipe;

    uv_connect_t connect_req;

    uv_thread_t thread;
};

/**
 * Create a multiplexed handler
 * This handler will allow the TCP listen socket to be split across multiple
 * workers, when the uv_multiplex_dispatch() is called.
 *
 * @param[in] m The multiplex handle
 * @param[in] listener TCP socket to multiplex on
 * @param[in] pipe_name The name of pipe that the dispatcher uses to
 *            communicate with the workers
 * @param[in] nworkers The number of workers to spawn
 * @param[in] worker_start The callback once the multiplexing has succeeded
 * @return 0 on success, -1 otherwise
 */
int uv_multiplex_init(uv_multiplex_t* m,
                      uv_tcp_t* listener,
                      const char* pipe_name,
                      unsigned int nworkers,
                      void (*worker_start)(
                          void* uv_tcp)
                      );

/**
 * Create worker
 *
 * @param[in] m The multiplex handle
 * @param[in] worker_id The id of the worker.
 *            This is between 0 and m->nworkers.
 * @param[in] udata User data.
 *            This is provided by listener->data in worker_start()
 * @return 0 on success, -1 otherwise
 */
int uv_multiplex_worker_create(uv_multiplex_t* m,
                               unsigned int worker_id,
                               void* udata);

/**
 * Start the multiplex operation
 * The worker threads will have the listen handle passed to them
 *
 * @param[in] m The multiplex handle
 * @return 0 on success, -1 otherwise
 */
int uv_multiplex_dispatch(uv_multiplex_t* m);

#endif /* UV_MULTIPLEX_H */
