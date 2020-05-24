#include "moar.h"

#ifdef _WIN32
#include <ws2tcpip.h>

#define sa_family_t unsigned int
#else
#include <sys/un.h>
#endif

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

static const size_t MAX_SUN_LEN = sizeof(((struct sockaddr_un *)NULL)->sun_path);

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

MVMuint16 MVM_address_port(MVMThreadContext *tc, MVMAddress *address) {
    switch (address->body.family) {
        case AF_INET:
            return ntohs(((struct sockaddr_in *)&address->body.storage)->sin_port);
        case AF_INET6:
            return ntohs(((struct sockaddr_in6 *)&address->body.storage)->sin6_port);
        default:
            MVM_exception_throw_adhoc(tc, "Can only get the port of an IP address");
    }
}

MVMuint32 MVM_address_flowinfo(MVMThreadContext *tc, MVMAddress *address) {
    if (address->body.family == AF_INET6)
        return ntohl(((struct sockaddr_in6 *)&address->body.storage)->sin6_flowinfo);
    else
        MVM_exception_throw_adhoc(tc, "Can only get the flowinfo of an IPv6 address");
}

MVMuint32 MVM_address_scope_id(MVMThreadContext *tc, MVMAddress *address) {
    if (address->body.family == AF_INET6)
        return ntohl(((struct sockaddr_in6 *)&address->body.storage)->sin6_scope_id);
    else
        MVM_exception_throw_adhoc(tc, "Can only get the scope ID of an IPv6 address");
}

MVMint64 MVM_address_family(MVMThreadContext *tc, MVMAddress *address) {
    return from_native_family(tc, address->body.family);
}

MVMint64 MVM_address_type(MVMThreadContext *tc, MVMAddress *address) {
    return from_native_type(tc, address->body.type);
}

MVMint64 MVM_address_protocol(MVMThreadContext *tc, MVMAddress *address) {
    return from_native_protocol(tc, address->body.protocol);
}

MVMObject * MVM_address_from_ipv4_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port,
        MVMint64 type, MVMint64 protocol) {
    MVMAddress     *address;
    struct in_addr  native_address;
    char           *ip;
    int             result;

    ip     = MVM_string_utf8_encode_C_string(tc, presentation);
    result = inet_pton(AF_INET, ip, &native_address);
    if (result == 0) {
        char *waste[] = { ip, NULL };
        MVM_exception_throw_adhoc_free(tc, waste,
            "Failed to create an IPv4 address from its presentation format (%s): no parse", ip);
    }
    else if (result == -1) {
        char *waste[] = { ip, NULL };
        MVM_exception_throw_adhoc_free(tc, waste,
            "Failed to create an IPv4 address from its presentation format (%s): %s", ip, strerror(errno));
    }
    else {
        MVMROOT(tc, presentation, {
            struct sockaddr_in socket_address;
            memset(&socket_address, 0, sizeof(socket_address));
            socket_address.sin_len    = sizeof(socket_address);
            socket_address.sin_family = AF_INET;
            socket_address.sin_port   = htons(port);
            memcpy(&socket_address.sin_addr, &native_address, sizeof(native_address));

            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, socket_address.sin_len);
            address->body.family   = AF_INET;
            address->body.type     = to_native_type(tc, type);
            address->body.protocol = to_native_protocol(tc, protocol);
        });
    }

    return (MVMObject *)address;
}

MVMObject * MVM_address_from_ipv6_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port, MVMuint32 flowinfo, MVMuint32 scope_id,
        MVMint64 type, MVMint64 protocol) {
    MVMAddress      *address;
    struct in6_addr  native_address;
    char            *ip;
    int              result;

    ip     = MVM_string_utf8_encode_C_string(tc, presentation);
    result = inet_pton(AF_INET6, ip, &native_address);
    if (result == 0) {
        char *waste[] = { ip, NULL };
        MVM_exception_throw_adhoc_free(tc, waste,
            "Failed to create an IPv6 address from its presentation format (%s): no parse", ip);
    }
    else if (result == -1) {
        char *waste[] = { ip, NULL };
        MVM_exception_throw_adhoc_free(tc, waste,
            "Failed to create an IPv6 address from its presentation format (%s): %s", ip, strerror(errno));
    }
    else {
        MVMROOT(tc, presentation, {
            struct sockaddr_in6 socket_address;
            memset(&socket_address, 0, sizeof(socket_address));
            socket_address.sin6_len      = sizeof(socket_address);
            socket_address.sin6_family   = AF_INET6;
            socket_address.sin6_port     = htons(port);
            socket_address.sin6_flowinfo = htonl(flowinfo);
            memcpy(&socket_address.sin6_addr, &native_address, sizeof(native_address));
            socket_address.sin6_scope_id = htonl(scope_id);

            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, socket_address.sin6_len);
            address->body.family   = AF_INET6;
            address->body.type     = to_native_type(tc, type);
            address->body.protocol = to_native_protocol(tc, protocol);
        });
    }

    return (MVMObject *)address;
}

MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path, MVMint64 type, MVMint64 protocol) {
#if defined(_WIN32) || !defined(AF_UNIX)
    MVM_exception_throw_adhoc(tc, "UNIX sockets are not supported by MoarVM on this platform");
#else
    MVMAddress *address;
    char       *path_cstr = MVM_string_utf8_encode_C_string(tc, path);
    size_t      sun_len   = strnlen(path_cstr, MAX_SUN_LEN);

    if (sun_len >= MAX_SUN_LEN) {
        char *waste[] = { path_cstr, NULL };
        MVM_exception_throw_adhoc_free(
            tc, waste,
            "Socket path '%s' is too long (max length supported by this platform is %zu characters)",
            path_cstr, MAX_SUN_LEN - 1
        );
    } else {
        struct sockaddr_un socket_address;
        memset(&socket_address, 0, sizeof(socket_address));
        socket_address.sun_family = AF_UNIX;
        strcpy(socket_address.sun_path, path_cstr);
        MVM_free(path_cstr);

        MVMROOT(tc, path, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, SUN_LEN(&socket_address));
            address->body.family   = AF_UNIX;
            address->body.type     = to_native_type(tc, type);
            address->body.protocol = to_native_protocol(tc, protocol);
        });

        return (MVMObject *)address;
    }
#endif
}

MVMString * MVM_address_to_presentation(MVMThreadContext *tc, MVMAddress *address) {
    MVMString *presentation;

    switch (address->body.family) {
        case AF_INET: {
            char            presentation_cstr[INET_ADDRSTRLEN];
            struct in_addr *native_address;

            native_address = &((struct sockaddr_in *)&address->body.storage)->sin_addr;
            if (inet_ntop(AF_INET, native_address, presentation_cstr, sizeof(presentation_cstr)) == NULL)
                MVM_exception_throw_adhoc(tc,
                    "Failed to format a presentation string for an IPv4 address: %s", strerror(errno));
            else {
                MVMROOT(tc, address, {
                    presentation = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, presentation_cstr);
                });
            }

            break;
        }
        case AF_INET6: {
            char             presentation_cstr[INET6_ADDRSTRLEN];
            struct in6_addr *native_address;

            native_address = &((struct sockaddr_in6 *)&address->body.storage)->sin6_addr;
            if (inet_ntop(AF_INET6, native_address, presentation_cstr, sizeof(presentation_cstr)) == NULL)
                MVM_exception_throw_adhoc(tc,
                    "Failed to format a presentation string for an IPv6 address: %s", strerror(errno));
            else {
                MVMROOT(tc, address, {
                    presentation = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, presentation_cstr);
                });
            }

            break;
        }
        case AF_UNIX: {
            MVMROOT(tc, address, {
                presentation = MVM_string_ascii_decode_nt(tc,
                    tc->instance->VMString, ((struct sockaddr_un *)&address->body.storage)->sun_path);
            });
            break;
        }
    }

    return presentation;
}

MVMObject * MVM_address_resolve_sync(MVMThreadContext *tc,
        MVMString *host, MVMuint16 port,
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
    snprintf(port_cstr, 8, "%"PRIu16"", port);

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
                address->body.family   = info->ai_family;
                address->body.type     = info->ai_socktype;
                address->body.protocol = info->ai_protocol;
                MVM_repr_push_o(tc, addresses, (MVMObject *)address);
            }
        });
    });

    freeaddrinfo(result);
    return addresses;
}
