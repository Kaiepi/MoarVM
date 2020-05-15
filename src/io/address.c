#include "moar.h"

static sa_family_t to_native_family(MVMThreadContext *tc, MVMint64 family) {
    switch (family) {
        case MVM_SOCKET_FAMILY_UNSPEC:
            return PF_UNSPEC;
        case MVM_SOCKET_FAMILY_INET:
            return PF_INET;
        case MVM_SOCKET_FAMILY_INET6:
            return PF_INET6;
        case MVM_SOCKET_FAMILY_UNIX:
            return PF_UNIX;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown network address family: %"PRIi64"", family);
    }
}

static MVMint64 from_native_family(MVMThreadContext *tc, sa_family_t family) {
    switch (family) {
        case PF_UNSPEC:
            return MVM_SOCKET_FAMILY_UNSPEC;
        case PF_INET:
            return MVM_SOCKET_FAMILY_INET;
        case PF_INET6:
            return MVM_SOCKET_FAMILY_INET6;
        case PF_UNIX:
            return MVM_SOCKET_FAMILY_UNIX;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown native network address family: %hhu", family);
    }
}

static int to_native_type(MVMThreadContext *tc, MVMint64 type) {
    switch (type) {
        case MVM_SOCKET_TYPE_ANY:
            return 0;
        case MVM_SOCKET_TYPE_STREAM:
            return SOCK_STREAM;
        case MVM_SOCKET_TYPE_DGRAM:
            return SOCK_DGRAM;
        case MVM_SOCKET_TYPE_SEQPACKET:
            return SOCK_SEQPACKET;
        case MVM_SOCKET_TYPE_RDM:
            return SOCK_RDM;
        case MVM_SOCKET_TYPE_RAW:
            return SOCK_RAW;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown network address type: %"PRIi64"", type);
    }
}

static int from_native_type(MVMThreadContext *tc, int type) {
    switch (type) {
        case 0:
            return MVM_SOCKET_TYPE_ANY;
        case SOCK_STREAM:
            return MVM_SOCKET_TYPE_STREAM;
        case SOCK_DGRAM:
            return MVM_SOCKET_TYPE_DGRAM;
        case SOCK_SEQPACKET:
            return MVM_SOCKET_TYPE_SEQPACKET;
        case SOCK_RDM:
            return MVM_SOCKET_TYPE_RDM;
        case SOCK_RAW:
            return MVM_SOCKET_TYPE_RAW;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown native network address type: %d", type);
    }
}

static int to_native_protocol(MVMThreadContext *tc, MVMint64 protocol) {
    switch (protocol) {
        case MVM_SOCKET_PROTOCOL_ANY:
            return 0;
        case MVM_SOCKET_PROTOCOL_TCP:
            return IPPROTO_TCP;
        case MVM_SOCKET_PROTOCOL_UDP:
            return IPPROTO_UDP;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown network protocol: %"PRIi64"", protocol);
    }
}

static MVMint64 from_native_protocol(MVMThreadContext *tc, int protocol) {
    switch (protocol) {
        case 0:
            return MVM_SOCKET_PROTOCOL_ANY;
        case IPPROTO_TCP:
            return MVM_SOCKET_PROTOCOL_TCP;
        case IPPROTO_UDP:
            return MVM_SOCKET_PROTOCOL_UDP;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown native network protocol: %d", protocol);
    }
}

MVMObject * MVM_address_resolve_sync(MVMThreadContext *tc,
        MVMString *host, MVMint64 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive) {
    char *host_cstr;
    char  port_cstr[8];

    struct addrinfo hints, *result;
    int             error;

    MVMObject *addresses;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = to_native_family(tc, family);
    hints.ai_socktype = to_native_type(tc, type);
    hints.ai_protocol = to_native_protocol(tc, protocol);
    hints.ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV;
    if (passive) hints.ai_flags |= AI_PASSIVE;

    host_cstr = MVM_string_utf8_encode_C_string(tc, host);
    snprintf(port_cstr, 8, "%"PRIi64"", port);

    MVM_gc_mark_thread_blocked(tc);
    error = getaddrinfo(host_cstr, port_cstr, &hints, &result);
    MVM_gc_mark_thread_unblocked(tc);
    if (error) {
        char *waste[] = { host_cstr, NULL };
        MVM_exception_throw_adhoc_free(
            tc, waste, "Failed to resolve host name '%s' with family %"PRIi64".\nError: %s",
            host_cstr, family, gai_strerror(error)
        );
    }
    MVM_free(host_cstr);

    MVMROOT(tc, host, {
        MVMAddress *address = NULL;
        addresses = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVMROOT2(tc, addresses, address, {
            struct addrinfo *info;
            for (info = result; info != NULL; info = info->ai_next) {
                address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                memcpy(&address->body.storage, info->ai_addr, info->ai_addrlen);
                address->body.family   = from_native_family(tc, info->ai_family);
                address->body.type     = from_native_type(tc, info->ai_socktype);
                address->body.protocol = from_native_protocol(tc, info->ai_protocol);
                MVM_repr_push_o(tc, addresses, (MVMObject *)address);
            }
        });
    });

    freeaddrinfo(result);
    return addresses;
}

MVMint64 MVM_address_family(MVMThreadContext *tc, MVMAddress *address) {
    return address->body.family;
}

MVMint64 MVM_address_type(MVMThreadContext *tc, MVMAddress *address) {
    return address->body.type;
}

MVMint64 MVM_address_protocol(MVMThreadContext *tc, MVMAddress *address) {
    return address->body.protocol;
}
