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
