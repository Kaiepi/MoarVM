/* Size of the pool for pending DNS queries. */
#define MVM_RESOLVER_POOL_LEN 31

/* Handle used to make a pending DNS query. */
struct MVMResolverHandle {
    uv_poll_t     handle;
    ares_socket_t connection;
};

/* Representation used by DNS resolvers. */
struct MVMResolverBody {
    ares_channel      channel;
    int               configured;
    MVMResolverHandle handles[MVM_RESOLVER_POOL_LEN];
    uv_sem_t          sem_handles;
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
