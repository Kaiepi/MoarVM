#include "moar.h"

/* if_nametoindex */
#ifdef _WIN32
#include <netioapi.h>
#else
#include <net/if.h>
#endif

MVMObject * MVM_address_from_ipv4_presentation(MVMThreadContext *tc, MVMString *presentation, MVMuint16 port) {
    char               *presentation_cstr;
    struct sockaddr_in  socket_address;
    MVMAddress         *address;
    int                 error;

    presentation_cstr = MVM_string_utf8_encode_C_string(tc, presentation);
    if ((error = uv_inet_pton(AF_INET, presentation_cstr, &socket_address.sin_addr)))
        MVM_exception_throw_adhoc_free(tc, (char * []){ presentation_cstr, NULL },
            "Error creating an IPv4 address from presentation-format string ('%s'): %s",
            presentation_cstr, uv_strerror(error));
    else {
        socket_address.sin_port   = htons(port);
        socket_address.sin_family = AF_INET;
        MVM_free(presentation_cstr);
    }

    MVMROOT(tc, presentation, {
        address                   = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
        memcpy(&address->body.storage, &socket_address, sizeof(struct sockaddr_in));
        MVM_address_set_length(&address->body, sizeof(struct sockaddr_in));
    });
    return (MVMObject *)address;
}

MVMObject * MVM_address_from_ipv6_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port, MVMString *zone_id) {
    char                *presentation_cstr;
    char                *zone_id_cstr;
    struct sockaddr_in6  socket_address;
    MVMAddress          *address;
    int                  error;

    presentation_cstr = MVM_string_utf8_encode_C_string(tc, presentation);
    if (strchr(presentation_cstr, '%')) {
        /* uv_inet_pton strips % from presentation strings. inet_pton treats
         * there being one as an error, so we shall too. */
        error = UV_EINVAL;
        goto presentation_error;
    }
    else if ((error = uv_inet_pton(AF_INET6, presentation_cstr, &socket_address.sin6_addr)))
        goto presentation_error;
    else {
        socket_address.sin6_family = AF_INET6;
        socket_address.sin6_port   = htons(port);
        if (zone_id) {
            zone_id_cstr = MVM_string_utf8_encode_C_string(tc, zone_id);
            if (!(socket_address.sin6_scope_id = if_nametoindex(zone_id_cstr))) {
#ifdef _MSC_VER
                socket_address.sin6_scope_id = strtoul(zone_id_cstr, zone_id_cstr + strlen(zone_id_cstr), 0);
                if (errno)
                    goto zone_error;
#else
                const char *error_cstr = NULL;
                socket_address.sin6_scope_id = strtonum(zone_id_cstr, 0, UINT32_MAX, &error_cstr);
                if (error_cstr)
                    goto zone_error;
#endif
            }
            MVM_free(zone_id_cstr);
        }
        MVM_free(presentation_cstr);
    }

    MVMROOT(tc, presentation, {
        address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
        memcpy(&address->body.storage, &socket_address, sizeof(struct sockaddr_in6));
        MVM_address_set_length(&address->body, sizeof(struct sockaddr_in6));
    });
    return (MVMObject *)address;

presentation_error:
    MVM_exception_throw_adhoc_free(tc, (char * []){ presentation_cstr, NULL },
        "Error creating an IPv6 address from presentation-format string ('%s'): %s",
        presentation_cstr, uv_strerror(error));

zone_error:
    MVM_exception_throw_adhoc_free(tc, (char * []){ presentation_cstr, zone_id_cstr, NULL },
        "Error creating an IPv6 address from presentation-format string ('%s') with zone ID ('%s'): "
        "not a network interface name or index",
        presentation_cstr, zone_id_cstr);
}

MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path) {
#ifdef MVM_HAS_PF_UNIX
    MVMuint64           path_len;
    char               *path_cstr;
    struct sockaddr_un  socket_address;
    MVMAddress         *address;

    path_cstr = MVM_string_utf8_encode(tc, path, &path_len, 0);
    if (path_len >= MVM_SUN_PATH_SIZE) {
        MVM_free(path_cstr);
        MVM_exception_throw_adhoc(tc,
            "UNIX socket address path is too long (max length supported by this platform is %zu characters)",
            MVM_SUN_PATH_SIZE - 1);
    }
    else {
        socket_address.sun_family = AF_UNIX;
        memcpy(socket_address.sun_path, path_cstr, path_len);
        MVM_free(path_cstr);
    }

    MVMROOT(tc, path, {
        MVMuint8 socket_address_size = sizeof(socket_address) - MVM_SUN_PATH_SIZE + path_len;
        address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
        memcpy(&address->body.storage, &socket_address, socket_address_size);
        MVM_address_set_length(&address->body, socket_address_size);
    });
    return (MVMObject *)address;
#else
    MVM_exception_throw_adhoc(tc, "UNIX sockets are not supported by MoarVM on this platform");
#endif
}

MVMuint16 MVM_address_get_port(MVMThreadContext *tc, MVMAddress *address) {
    switch (MVM_address_get_family(&address->body)) {
        case AF_INET:
            return ntohs(address->body.storage.sin.sin_port);
        case AF_INET6:
            return ntohs(address->body.storage.sin6.sin6_port);
        default:
            MVM_exception_throw_adhoc(tc, "Can only get the port of an IP address");
    }
}

MVMuint32 MVM_address_get_scope_id(MVMThreadContext *tc, MVMAddress *address) {
    if (MVM_address_get_family(&address->body) == AF_INET6)
        return address->body.storage.sin6.sin6_scope_id;
    else
        MVM_exception_throw_adhoc(tc, "Can only get the scope ID of an IPv6 address");
}

MVMString * MVM_address_to_string(MVMThreadContext *tc, MVMAddress *address) {
    sa_family_t  family;
    MVMString   *address_str;

    switch (family = MVM_address_get_family(&address->body)) {
        case AF_INET: {
            char address_cstr[INET_ADDRSTRLEN];
            int  error;

            if ((error = uv_inet_ntop(AF_INET,
                    &address->body.storage.sin.sin_addr, address_cstr, sizeof(address_cstr))))
                MVM_exception_throw_adhoc(tc,
                    "Error creating an IPv4 address presentation-format string: %s",
                    uv_strerror(error));
            else {
                MVMROOT(tc, address, {
                    address_str = MVM_string_utf8_decode(tc, tc->instance->VMString,
                        address_cstr, strnlen(address_cstr, sizeof(address_cstr) - 1));
                });
            }
            break;
        }
        case AF_INET6: {
            char address_cstr[INET6_ADDRSTRLEN];
            int  error;

            if ((error = uv_inet_ntop(AF_INET6,
                    &address->body.storage.sin6.sin6_addr, address_cstr, sizeof(address_cstr))))
                MVM_exception_throw_adhoc(tc,
                    "Error creating an IPv6 address presentation-format string: %s",
                    uv_strerror(error));
            else {
                MVMROOT(tc, address, {
                    address_str = MVM_string_utf8_decode(tc, tc->instance->VMString,
                        address_cstr, strnlen(address_cstr, sizeof(address_cstr) - 1));
                });
            }
            break;
        }
#ifdef MVM_HAS_PF_UNIX
        case AF_UNIX:
            MVMROOT(tc, address, {
                address_str = MVM_string_utf8_c8_decode(tc, tc->instance->VMString, address->body.storage.sun.sun_path,
                    MVM_address_get_length(&address->body) - sizeof(struct sockaddr_un) + MVM_SUN_PATH_SIZE);
            });
            break;
#endif
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported native address family: %hu", family);
            break;
    }

    return address_str;
}
