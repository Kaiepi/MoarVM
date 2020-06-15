#define MVM_RESOLVER_POOL_SIZE 16

/* Info pertaining to a pending DNS query. */
struct MVMResolverQueryInfo;

struct MVMResolverContext {
    ares_channel  channel;
    int           configured;
    uv_sem_t      sem_query;

    MVMThreadContext *tc;
    int               work_idx;
    uv_loop_t        *loop;
    ares_socket_t     connection;
    uv_poll_t        *handle;
};

/* Representation used by DNS resolvers. */
struct MVMResolverBody {
    MVMResolverContext contexts[MVM_RESOLVER_POOL_SIZE];
    uv_sem_t           sem_contexts;
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
