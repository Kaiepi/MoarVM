#include "moar.h"

#ifdef _WIN32
#include <ws2tcpip.h>

#define sa_family_t unsigned int
#else
#include <sys/un.h>
#endif

/* This representation's function pointer table. */
static const MVMREPROps MVMAddress_this_repr;

/* Creates a new type object of this representation, and associates it with
 * the given HOW. */
static MVMObject * type_object_for(MVMThreadContext *tc, MVMObject *HOW) {
    MVMSTable *st = MVM_gc_allocate_stable(tc, &MVMAddress_this_repr, HOW);

    MVMROOT(tc, st, {
        MVMObject *obj = MVM_gc_allocate_type_object(tc, st);
        MVM_ASSIGN_REF(tc, &(st->header), st->WHAT, obj);
        st->size = sizeof(MVMAddress);
    });

    return st->WHAT;
}

/* Initializes the address. */
static void initialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data) {
    /* Nothing doing. */
}

/* Copies the body of one object to another. */
static void copy_to(MVMThreadContext *tc, MVMSTable *st, void *src, MVMObject *dest_root, void *dest) {
    MVMAddressBody *src_body  = (MVMAddressBody *)src;
    MVMAddressBody *dest_body = (MVMAddressBody *)dest;
    memcpy(&dest_body->storage, &src_body->storage, sizeof(struct sockaddr_storage));
}

static const MVMStorageSpec storage_spec = {
    MVM_STORAGE_SPEC_REFERENCE, /* inlineable */
    0,                          /* bits */
    0,                          /* align */
    MVM_STORAGE_SPEC_BP_NONE,   /* boxed_primitive */
    0,                          /* can_box */
    0,                          /* is_unsigned */
};

/* Gets the storage specification for this representation. */
static const MVMStorageSpec * get_storage_spec(MVMThreadContext *tc, MVMSTable *st) {
    return &storage_spec;
}

/* Compose the representation. */
static void compose(MVMThreadContext *tc, MVMSTable *st, MVMObject *info) {
    /* Nothing doing. */
}

/* Initializes the representation. */
const MVMREPROps * MVMAddress_initialize(MVMThreadContext *tc) {
    return &MVMAddress_this_repr;
}

static const MVMREPROps MVMAddress_this_repr = {
    type_object_for,
    MVM_gc_allocate_object,
    initialize,
    copy_to,
    MVM_REPR_DEFAULT_ATTR_FUNCS,
    MVM_REPR_DEFAULT_BOX_FUNCS,
    MVM_REPR_DEFAULT_POS_FUNCS,
    MVM_REPR_DEFAULT_ASS_FUNCS,
    MVM_REPR_DEFAULT_ELEMS,
    get_storage_spec,
    NULL, /* change_type */
    NULL, /* serialize */
    NULL, /* deserialize */
    NULL, /* serialize_repr_data */
    NULL, /* deserialize_repr_data */
    NULL, /* deserialize_stable_size */
    NULL, /* gc_mark */
    NULL, /* gc_free */
    NULL, /* gc_cleanup */
    NULL, /* gc_mark_repr_data */
    NULL, /* gc_free_repr_data */
    compose,
    NULL, /* spesh */
    "MVMAddress", /* name */
    MVM_REPR_ID_MVMAddress,
    NULL, /* unmanaged_size */
    NULL, /* describe_refs */
};

static const size_t MAX_SUN_LEN = sizeof(((struct sockaddr_un *)NULL)->sun_path);

sa_family_t MVM_address_to_native_family(MVMThreadContext *tc, MVMint64 family) {
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

MVMint64 MVM_address_from_native_family(MVMThreadContext *tc, sa_family_t family) {
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

int MVM_address_to_native_type(MVMThreadContext *tc, MVMint64 type) {
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

MVMint64 MVM_address_from_native_type(MVMThreadContext *tc, int type) {
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

int MVM_address_to_native_protocol(MVMThreadContext *tc, MVMint64 protocol) {
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

MVMint64 MVM_address_from_native_protocol(MVMThreadContext *tc, int protocol) {
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
    switch (address->body.storage.ss_family) {
        case AF_INET:
            return ntohs(((struct sockaddr_in *)&address->body.storage)->sin_port);
        case AF_INET6:
            return ntohs(((struct sockaddr_in6 *)&address->body.storage)->sin6_port);
        default:
            MVM_exception_throw_adhoc(tc, "Can only get the port of an IP address");
    }
}

MVMuint32 MVM_address_flowinfo(MVMThreadContext *tc, MVMAddress *address) {
    if (address->body.storage.ss_family == AF_INET6)
        return ntohl(((struct sockaddr_in6 *)&address->body.storage)->sin6_flowinfo);
    else
        MVM_exception_throw_adhoc(tc, "Can only get the flowinfo of an IPv6 address");
}

MVMuint32 MVM_address_scope_id(MVMThreadContext *tc, MVMAddress *address) {
    if (address->body.storage.ss_family == AF_INET6)
        return ((struct sockaddr_in6 *)&address->body.storage)->sin6_scope_id;
    else
        MVM_exception_throw_adhoc(tc, "Can only get the scope ID of an IPv6 address");
}

MVMObject * MVM_address_from_ipv4_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port) {
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
        struct sockaddr_in socket_address;
        memset(&socket_address, 0, sizeof(socket_address));
        socket_address.sin_len    = sizeof(socket_address);
        socket_address.sin_family = AF_INET;
        socket_address.sin_port   = htons(port);
        memcpy(&socket_address.sin_addr, &native_address, sizeof(native_address));

        MVMROOT(tc, presentation, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, socket_address.sin_len);
        });
    }

    return (MVMObject *)address;
}

MVMObject * MVM_address_from_ipv6_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port, MVMuint32 flowinfo, MVMuint32 scope_id) {
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
        struct sockaddr_in6 socket_address;
        memset(&socket_address, 0, sizeof(socket_address));
        socket_address.sin6_len      = sizeof(socket_address);
        socket_address.sin6_family   = AF_INET6;
        socket_address.sin6_port     = htons(port);
        socket_address.sin6_flowinfo = htonl(flowinfo);
        memcpy(&socket_address.sin6_addr, &native_address, sizeof(native_address));
        socket_address.sin6_scope_id = scope_id;

        MVMROOT(tc, presentation, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, socket_address.sin6_len);
        });
    }

    return (MVMObject *)address;
}

MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path) {
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
        /* XXX TODO: sun_len isn't POSIX... so what platforms don't have it and
         * need to be handled differently? */
        socket_address.sun_len    = sizeof(socket_address) - sizeof(socket_address.sun_path) + sun_len;
        socket_address.sun_family = AF_UNIX;
        strcpy(socket_address.sun_path, path_cstr);
        MVM_free(path_cstr);

        MVMROOT(tc, path, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, socket_address.sun_len);
        });

        return (MVMObject *)address;
    }
#endif
}

MVMString * MVM_address_to_presentation(MVMThreadContext *tc, MVMAddress *address) {
    MVMString *presentation;

    switch (address->body.storage.ss_family) {
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
