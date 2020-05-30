#include "moar.h"

#ifdef _WIN32
#include <ws2tcpip.h>

#define sa_family_t unsigned int
#endif

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

MVMObject * MVM_io_dns_resolve(MVMThreadContext *tc,
        MVMString *host, MVMuint16 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive) {
    char *host_cstr;
    char  port_cstr[8];

    struct addrinfo hints, *result;
    int             error;

    MVMObject *arr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = MVM_address_to_native_family(tc, family);
    hints.ai_socktype = MVM_address_to_native_type(tc, type);
    hints.ai_protocol = MVM_address_to_native_protocol(tc, protocol);
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
        arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVMROOT(tc, arr, {
            struct addrinfo *native_address_info;
            for (
                native_address_info = result;
                native_address_info != NULL;
                native_address_info = native_address_info->ai_next
            ) {
                MVMObject  *address_info   = NULL;
                MVMAddress *address        = NULL;
                MVMObject  *boxed_family   = NULL;
                MVMObject  *boxed_type     = NULL;
                MVMObject  *boxed_protocol = NULL;
                MVMROOT5(tc, address_info, address, boxed_family, boxed_type, boxed_protocol, {
                    address_info = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    address      = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                    memcpy(&address->body.storage, native_address_info->ai_addr, native_address_info->ai_addrlen);

                    boxed_family   = MVM_repr_box_int(tc,
                        tc->instance->boot_types.BOOTInt,
                        MVM_address_from_native_family(tc, native_address_info->ai_family));
                    boxed_type     = MVM_repr_box_int(tc,
                        tc->instance->boot_types.BOOTInt,
                        MVM_address_from_native_type(tc, native_address_info->ai_socktype));
                    boxed_protocol = MVM_repr_box_int(tc,
                        tc->instance->boot_types.BOOTInt,
                        MVM_address_from_native_protocol(tc, native_address_info->ai_protocol));

                    MVM_repr_push_o(tc, address_info, (MVMObject *)address);
                    MVM_repr_push_o(tc, address_info, boxed_family);
                    MVM_repr_push_o(tc, address_info, boxed_type);
                    MVM_repr_push_o(tc, address_info, boxed_protocol);
                    MVM_repr_push_o(tc, arr, address_info);
                });
            }
        });
    });

    freeaddrinfo(result);
    return arr;
}
