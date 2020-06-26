#define MVM_RESOLVER_POOL_SIZE 16

/* A DNS resolution context. This keeps track of state that needs to persist
   between DNS queries. The body of a Resolver keeps a pool of these, since
   c-ares' channels misbehave when being used over multiple threads. */
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
