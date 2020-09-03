/* Representation that manages a context from which DNS queries can be made. */
struct MVMResolverBody {
#ifdef HAVE_WINDNS
    /* WinDNS expects DNS query configuration to be given upon each query made.
     * In this case, the DNS resolver's job is simply to keep track of this
     * information between queries:
     *
     * TODO */
#else
    /* LDNS manages DNS query configuration through a DNS resolver struct. The
     * DNS resolver's job is simply to wrap this struct, which we'll call a
     * DNS resolution context to avoid confusion with the resolver object: */
    ldns_resolver *context;
    /* The asyncdnsquery op requires a buffer type to be used when a query type
     * is unsupported. This gives the op too many operands! We store the type
     * to be used here, since this shouldn't change between queries anyway. */
    MVMObject     *buf_type;
#endif
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
