/* Representation used by VM-level network addresses. */
struct MVMAddressBody {
    /* The native address. */
    struct sockaddr_storage storage;
    /* The address' family. */
    sa_family_t family;
    /* The address' socket type. */
    int type;
    /* The address' protocol. */
    int protocol;
};

struct MVMAddress {
    MVMObject      common;
    MVMAddressBody body;
};

const MVMREPROps * MVMAddress_initialize(MVMThreadContext *tc);
