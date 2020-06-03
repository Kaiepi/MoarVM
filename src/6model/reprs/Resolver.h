struct MVMResolverQueryInfo;

/* Representation used by DNS resolvers. */
struct MVMResolverBody {
    /* The DNS resolution context. */
    ares_channel           channel;
    /* Whether or not the DNS resolution context has been configured. */
    int                    configured;
    /* Information pertaining to any pending DNS query. */
    MVMResolverQueryInfo **pending_queries;
    /* The maximum number of pending queries that can exist. */
    size_t                 pending_queries_size;
    /* Mutex protecting any pending DNS query. */
    uv_mutex_t            *mutex_pending_queries;
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

/* Info pertaining to a pending DNS query. */
struct MVMResolverQueryInfo {
    MVMResolver *resolver;
    char        *question;
    int          type;
    int          class;

    MVMThreadContext *tc;
    int               work_idx;
    uv_poll_t        *handle;
    ares_socket_t     connection;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
