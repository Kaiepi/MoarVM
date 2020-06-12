/* The maximum number of DNS resolver contexts to use in the DNS resolver pool. */
#define MVM_RESOLVER_CONTEXTS 8

/* Info pertaining to a pending DNS query. */
struct MVMResolverQueryInfo;

/* A DNS resolution context. This keeps track of state pertaining to DNS
 * resolution that is persistent between queries. */
struct MVMResolverContext {
    /* The c-ares channel to use with this context. */
    ares_channel          channel;
    /* Whether or not this context's channel has been configured. */
    int                   configured;
    /* Information pertaining to any pending DNS query being made from this
     * context. */
    MVMResolverQueryInfo *query_info;
    /* Read/write lock for pending DNS query info. */
    uv_rwlock_t          *rwlock_query_info;
};

/* Representation used by DNS resolvers. */
struct MVMResolverBody {
    /* A pool of DNS resolution contexts. */
    MVMResolverContext  contexts[MVM_RESOLVER_CONTEXTS];
    /* Semaphore protecting the DNS resolution context pool. */
    uv_sem_t           *sem_contexts;
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

struct MVMResolverQueryInfo {
    MVMResolver *resolver;
    char        *question;
    int          type;
    int          class;

    MVMThreadContext   *tc;
    int                 work_idx;
    uv_loop_t          *loop;

    MVMResolverContext *context;
    ares_socket_t       connection;
    uv_timer_t         *timer;
    uv_poll_t          *handle;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
