#define NUM_FAMILIES_WANTED 4
#define NUM_TYPES_WANTED 6
#define NUM_PROTOCOLS_WANTED 3

struct MVMSocketFamily {
    const char  *name;
    MVMint64     runtime;
    sa_family_t  native;
};

static const MVMSocketFamily MVM_io_socket_families[NUM_FAMILIES_WANTED] = {
    { "PF_UNSPEC", 0, PF_UNSPEC },
    { "PF_INET", 1, PF_INET },
    { "PF_INET6", 2, PF_INET6 },
    { "PF_UNIX", 3, PF_UNIX },
};

MVM_STATIC_INLINE const MVMSocketFamily * MVM_io_socket_runtime_family(MVMThreadContext *tc, MVMint64 runtime) {
    const MVMSocketFamily *family;
    for (
        family = MVM_io_socket_families;
        family < MVM_io_socket_families + NUM_FAMILIES_WANTED;
        ++family
    ) {
        if (family->runtime == runtime)
            return family;
    }
    MVM_exception_throw_adhoc(tc, "Unknown socket family: %"PRIi64"", runtime);
}

MVM_STATIC_INLINE const MVMSocketFamily * MVM_io_socket_native_family(MVMThreadContext *tc, sa_family_t native) {
    const MVMSocketFamily *family;
    for (
        family = MVM_io_socket_families;
        family < MVM_io_socket_families + NUM_FAMILIES_WANTED;
        ++family
    ) {
        if (family->native == native)
            return family;
    }
    MVM_exception_throw_adhoc(tc, "Unsupported native socket family: %hu", native);
}

struct MVMSocketType {
    const char *name;
    MVMint64    runtime;
    int         native;
};

static const MVMSocketType MVM_io_socket_types[NUM_TYPES_WANTED] = {
    { "SOCK_ANY", 0, 0 },
    { "SOCK_STREAM", 1, SOCK_STREAM },
    { "SOCK_DGRAM", 2, SOCK_DGRAM },
    { "SOCK_RAW", 3, SOCK_RAW },
    { "SOCK_RDM", 4, SOCK_RDM },
    { "SOCK_SEQPACKET", 5, SOCK_SEQPACKET },
};

MVM_STATIC_INLINE const MVMSocketType * MVM_io_socket_runtime_type(MVMThreadContext *tc, MVMint64 runtime) {
    const MVMSocketType *type;
    for (
        type = MVM_io_socket_types;
        type < MVM_io_socket_types + NUM_TYPES_WANTED;
        ++type
    ) {
        if (type->runtime == runtime)
            return type;
    }
    MVM_exception_throw_adhoc(tc, "Unknown socket type: %"PRIi64"", runtime);
}

MVM_STATIC_INLINE const MVMSocketType * MVM_io_socket_native_type(MVMThreadContext *tc, int native) {
    const MVMSocketType *type;
    for (
        type = MVM_io_socket_types;
        type < MVM_io_socket_types + NUM_TYPES_WANTED;
        ++type
    ) {
        if (type->native == native)
            return type;
    }
    MVM_exception_throw_adhoc(tc, "Unsupported native socket type: %d", native);
}

struct MVMSocketProtocol {
    const char *name;
    MVMint64    runtime;
    int         native;
};

static const MVMSocketProtocol MVM_io_socket_protocols[NUM_PROTOCOLS_WANTED] = {
    { "IPPROTO_ANY", 0, 0 },
    { "IPPROTO_TCP", 1, IPPROTO_TCP },
    { "IPPROTO_UDP", 2, IPPROTO_UDP },
};

MVM_STATIC_INLINE const MVMSocketProtocol * MVM_io_socket_runtime_protocol(MVMThreadContext *tc, MVMint64 runtime) {
    const MVMSocketProtocol *protocol;
    for (
        protocol = MVM_io_socket_protocols;
        protocol < MVM_io_socket_protocols + NUM_PROTOCOLS_WANTED;
        ++protocol
    ) {
        if (protocol->runtime == runtime)
            return protocol;
    }
    MVM_exception_throw_adhoc(tc, "Unknown socket protocol: %"PRIi64"", runtime);
}

MVM_STATIC_INLINE const MVMSocketProtocol * MVM_io_socket_native_protocol(MVMThreadContext *tc, int native) {
    const MVMSocketProtocol *protocol;
    for (
        protocol = MVM_io_socket_protocols;
        protocol < MVM_io_socket_protocols + NUM_PROTOCOLS_WANTED;
        ++protocol
    ) {
        if (protocol->native == native)
            return protocol;
    }
    MVM_exception_throw_adhoc(tc, "Unsupported native socket protocol: %d", native);
}

#undef NUM_FAMILIES_WANTED
#undef NUM_TYPES_WANTED
#undef NUM_PROTOCOLS_WANTED
