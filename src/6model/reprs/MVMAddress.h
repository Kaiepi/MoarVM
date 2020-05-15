/* Representation used by VM-level network addresses. */
struct MVMAddressBody {
    /* The native address. */
    struct sockaddr_storage storage;
    /* The address' family. */
    MVMint64 family;
    /* The address' socket type. */
    MVMint64 type;
    /* The address' protocol. */
    MVMint64 protocol;
};

struct MVMAddress {
    MVMObject      common;
    MVMAddressBody body;
};

const MVMREPROps * MVMAddress_initialize(MVMThreadContext *tc);
