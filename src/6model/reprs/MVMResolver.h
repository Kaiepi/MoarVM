#ifndef HAVE_WINDNS
union MVMResolverIPAddress {
    struct sockaddr_in      ip4;
    struct sockaddr_in6     ip6;
    struct sockaddr         any;
    struct sockaddr_storage all;
};
#endif

/* Representation that manages a context from which DNS queries can be made. */
struct MVMResolverBody {
#ifdef HAVE_WINDNS
    /* TODO */
#else
    /* LDNS manages DNS resolution configuration with a resolver structure.
     * We'll call this a context to avoid confusion with our own resolver
     * objects: */
    ldns_resolver        *context;
    /* LDNS resolvers store name servers as their addresses would be
     * represented in A/AAAA queries (meaning no ports or scope IDs), so we
     * need to keep track of these ourselves: */
    MVMResolverIPAddress *name_servers;
    size_t                name_servers_count;
    /* Whether or not this resolver's context has been configured: */
    AO_T                  configured;

    /* The asyncdnsquery op requires a buffer type to be used when a query type
     * is unsupported. This gives the op more operands than we support! We
     * store the type to be used here, since this should always be a uint8
     * array of some sort anyway: */
    MVMObject *buf_type;
#endif
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);

void MVM_resolver_configure(MVMThreadContext *tc, MVMResolver *resolver,
        MVMArray *name_servers, MVMuint16 default_port, MVMint64 tcp_only,
        MVMObject *buf_type);
