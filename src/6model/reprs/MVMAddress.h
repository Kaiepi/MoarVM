/* Representation used by VM-level network addresses. */
struct MVMAddressBody {
    /* The native address. */
    struct sockaddr_storage storage;
};

struct MVMAddress {
    MVMObject      common;
    MVMAddressBody body;
};

const MVMREPROps * MVMAddress_initialize(MVMThreadContext *tc);
