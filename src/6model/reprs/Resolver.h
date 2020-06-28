/* Size of the pool for pending DNS queries.
 * This must be a prime number in order for hashing of file descriptors to work. */
#define MVM_RESOLVER_POOL_SIZE 31

/* Handle used to make a pending DNS query. */
struct MVMResolverHandle {
    uv_poll_t    handle;
    AO_t         connection;
    MVMResolver *resolver;
};

/* Representation used by DNS resolvers. */
struct MVMResolverBody {
    ares_channel      channel;
    int               configured;
    uv_mutex_t        mutex_configured;
    MVMResolverHandle handles[MVM_RESOLVER_POOL_SIZE];
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
