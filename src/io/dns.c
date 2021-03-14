#include "moar.h"

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

MVMObject * MVM_io_dns_lookup(MVMThreadContext *tc, MVMString *hostname,
        MVMint64 protocol_family, MVMint64 socket_type, MVMint64 protocol_type,
        MVMint64 packed) {
    MVMuint16         port;
    MVMint64          flags;
    char             *hostname_cstr;
    char              port_cstr[6];
    unsigned int      interval_id;
    struct addrinfo   hints, *result;
    int               error;

    port          = packed & 0xFFFF;
    flags         = packed >> 16;
    hostname_cstr = hostname ? MVM_string_ascii_encode_any(tc, hostname) : NULL;
    snprintf(port_cstr, sizeof(port_cstr), "%"PRIu16"", port);

    memset(&hints, 0, sizeof(hints));
    switch (protocol_family) {
        case MVM_PROTOCOL_FAMILY_UNSPEC:
            hints.ai_family = AF_UNSPEC;
            break;
        case MVM_PROTOCOL_FAMILY_INET:
            hints.ai_family = AF_INET;
            break;
        case MVM_PROTOCOL_FAMILY_INET6:
            hints.ai_family = AF_INET6;
            break;
        case MVM_PROTOCOL_FAMILY_UNIX:
            hints.ai_family = AF_UNIX;
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown protocol family: %"PRIi64"", protocol_family);
    }
    switch (socket_type) {
        case MVM_SOCKET_TYPE_ANY:
            hints.ai_socktype = 0;
            break;
        case MVM_SOCKET_TYPE_STREAM:
            hints.ai_socktype = SOCK_STREAM;
            break;
        case MVM_SOCKET_TYPE_DGRAM:
            hints.ai_socktype = SOCK_DGRAM;
            break;
        case MVM_SOCKET_TYPE_RAW:
            hints.ai_socktype = SOCK_RAW;
            break;
        case MVM_SOCKET_TYPE_RDM:
            hints.ai_socktype = SOCK_RDM;
            break;
        case MVM_SOCKET_TYPE_SEQPACKET:
            hints.ai_socktype = SOCK_SEQPACKET;
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown socket type: %"PRIi64"", socket_type);
    }
    switch (protocol_type) {
        case MVM_PROTOCOL_TYPE_ANY:
            hints.ai_protocol = 0;
            break;
        case MVM_PROTOCOL_TYPE_TCP:
            hints.ai_protocol = IPPROTO_TCP;
            break;
        case MVM_PROTOCOL_TYPE_UDP:
            hints.ai_protocol = IPPROTO_UDP;
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unknown protocol type: %"PRIi64"", protocol_type);
    }
    hints.ai_flags = AI_NUMERICSERV;
    if (flags & MVM_DNS_FLAG_ADDRCONFIG)
        hints.ai_flags |= AI_ADDRCONFIG;
    if (flags & MVM_DNS_FLAG_PASSIVE)
        hints.ai_flags |= AI_PASSIVE;

    interval_id = MVM_telemetry_interval_start(tc, "DNS resolution");
    MVM_gc_mark_thread_blocked(tc);
    error = getaddrinfo(hostname_cstr, port_cstr, &hints, &result);
    MVM_gc_mark_thread_unblocked(tc);
    MVM_telemetry_interval_stop(tc, interval_id, "DNS resolution");

    if (error) {
        char *waste[] = { hostname_cstr, NULL };
        MVM_exception_throw_adhoc_free(tc, waste,
            "Error resolving hostname '%s' with family %"PRIi64" and type %"PRIi64": %s",
            hostname_cstr, protocol_family, socket_type, gai_strerror(error));
    }
    else {
        struct addrinfo *info;
        MVMObject       *arr;
        MVMAddress      *address;
        MVMint64         sa_family, family, type, protocol;

        MVM_free(hostname_cstr);
        MVMROOT(tc, hostname, {
            arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        });
        MVMROOT2(tc, hostname, arr, {
            for (info = result; info; info = info->ai_next) {
                switch (info->ai_addr->sa_family) {
                    case PF_INET:
                        sa_family = MVM_PROTOCOL_FAMILY_INET;
                        break;
                    case PF_INET6:
                        sa_family = MVM_PROTOCOL_FAMILY_INET6;
                        break;
                    default:
                        continue;
                }

                switch (info->ai_family) {
                    case AF_UNSPEC:
                        family = MVM_PROTOCOL_FAMILY_UNSPEC;
                        break;
                    case AF_INET:
                        family = MVM_PROTOCOL_FAMILY_INET;
                        break;
                    case AF_INET6:
                        family = MVM_PROTOCOL_FAMILY_INET6;
                        break;
                    default:
                        continue;
                }

                switch (info->ai_socktype) {
                    case 0:
                        type = MVM_SOCKET_TYPE_ANY;
                        break;
                    case SOCK_STREAM:
                        type = MVM_SOCKET_TYPE_STREAM;
                        break;
                    case SOCK_DGRAM:
                        type = MVM_SOCKET_TYPE_DGRAM;
                        break;
                    case SOCK_RAW:
                        type = MVM_SOCKET_TYPE_RAW;
                        break;
                    case SOCK_RDM:
                        type = MVM_SOCKET_TYPE_RDM;
                        break;
                    case SOCK_SEQPACKET:
                        type = MVM_SOCKET_TYPE_SEQPACKET;
                        break;
                    default:
                        continue;
                }

                switch (info->ai_protocol) {
                    case 0:
                        protocol = MVM_PROTOCOL_TYPE_ANY;
                        break;
                    case IPPROTO_TCP:
                        protocol = MVM_PROTOCOL_TYPE_TCP;
                        break;
                    case IPPROTO_UDP:
                        protocol = MVM_PROTOCOL_TYPE_UDP;
                        break;
                    default:
                        continue;
                }

                MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, sa_family));

                address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                memcpy(&address->body.storage, info->ai_addr, info->ai_addrlen);
                MVM_io_address_set_length(&address->body, info->ai_addrlen);
                MVM_repr_push_o(tc, arr, (MVMObject *)address);

                MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, family));
                MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, type));
                MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, protocol));
            }
        });
        freeaddrinfo(result);
        return arr;
    }
}

