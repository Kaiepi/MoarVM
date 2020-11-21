/* Stores any type of socket address supported by MoarVM. */
union MVMAddressStorage {
    struct sockaddr         sa;
    struct sockaddr_storage ss;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
#ifdef MVM_HAS_PF_UNIX
    struct sockaddr_un      sun;
#endif
};

/* Representation for VM-level socket addresses. */
struct MVMAddressBody {
    /* A native socket address. */
    MVMAddressStorage storage;
#ifndef MVM_HAS_SA_LEN
    socklen_t         length;
#endif
};

struct MVMAddress {
    MVMObject      common;
    MVMAddressBody body;
};

const MVMREPROps * MVMAddress_initialize(MVMThreadContext *tc);

MVM_STATIC_INLINE socklen_t MVM_address_get_length(MVMAddressBody *body) {
#ifdef MVM_HAS_SA_LEN
    return body->storage.sa.sa_len;
#else
    return body->length;
#endif
}

MVM_STATIC_INLINE void MVM_address_set_length(MVMAddressBody *body, MVMuint8 len) {
#ifdef MVM_HAS_SA_LEN
    body->storage.sa.sa_len = len;
#else
    body->length = len;
#endif
}

MVM_STATIC_INLINE sa_family_t MVM_address_get_family(MVMAddressBody *body) {
    return body->storage.sa.sa_family;
}
