/* The number of DNS resolution contexts that queries can be made from.  While
 * one UDNS context could be used, because it only has one socket to make DNS
 * queries with and the library makes it so packets are emitted in the same
 * order they are sent in, this would make it so Happy Eyeballs v2 address
 * sorting never happens. A context to make a DNS query from is selected
 * randomly using this macro, so do not make this anything other than a power
 * of 2! */
#define MVM_RES_POOL_LEN 8

/* Representation used by DNS resolvers to handle a context from which DNS
 * queries can be made. */
struct MVMResolverBody {
    struct dns_ctx *ctx;
    uv_poll_t      *handle;
    MVMint32        configured;
};

struct MVMResolver {
    MVMObject       common;
    MVMResolverBody body;
};

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc);
