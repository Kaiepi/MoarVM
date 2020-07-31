#include "moar.h"

#ifdef _MSC_VER
#include <ws2tcpip.h>

#define snprintf _snprintf
#else
#include <sys/socket.h>
#endif

/* Max port is 65535. */
#define MAX_PORT_SIZE 6

MVMObject * MVM_io_dns_resolve(MVMThreadContext *tc,
        MVMString *hostname, MVMuint16 port,
        MVMint64 family_value, MVMint64 type_value, MVMint64 protocol_value,
        MVMint64 passive) {
    char                    *hostname_cstr;
    char                     port_cstr[MAX_PORT_SIZE];
    const MVMSocketFamily   *family;
    const MVMSocketType     *type;
    const MVMSocketProtocol *protocol;
    unsigned int             interval_id;
    struct addrinfo          hints, *result;
    int                      error;

    hostname_cstr = hostname ? MVM_string_utf8_encode_C_string(tc, hostname) : NULL;
    snprintf(port_cstr, MAX_PORT_SIZE, "%"PRIu16"", port);
    family        = MVM_io_socket_runtime_family(tc, family_value);
    type          = MVM_io_socket_runtime_type(tc, type_value);
    protocol      = MVM_io_socket_runtime_protocol(tc, protocol_value);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family->native;
    hints.ai_socktype = type->native;
    hints.ai_protocol = protocol->native;
    hints.ai_flags    = AI_NUMERICSERV | AI_ADDRCONFIG;
    if (passive)
        hints.ai_flags |= AI_PASSIVE;

    interval_id = MVM_telemetry_interval_start(tc, "DNS resolution");
    MVM_gc_mark_thread_blocked(tc);
    error = getaddrinfo(hostname_cstr, port_cstr, &hints, &result);
    MVM_gc_mark_thread_unblocked(tc);
    MVM_telemetry_interval_stop(tc, interval_id, "DNS resolution");

    if (error) {
        char *waste[] = { hostname_cstr, NULL };
        MVM_exception_throw_adhoc_free(tc, waste,
            "Error resolving hostname '%s' with family %s and type %s: %s",
            hostname_cstr, family->name, type->name, gai_strerror(error));
    }
    else {
        MVMObject       *arr;
        struct addrinfo *info;

        MVMROOT(tc, hostname, {
            arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        });
        for (info = result; info; info = info->ai_next) {
            switch (info->ai_protocol) {
                case 0:
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                    MVMROOT2(tc, hostname, arr, {
                        MVMObject *address_info = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        MVMROOT(tc, address_info, {
                            MVMAddress *address;

                            /* On Windows, the family included in the address
                             * info may be PF_UNSPEC. For this reason, we need
                             * to include the address' real family along with
                             * the address info's family. */
                            MVM_repr_push_o(tc, address_info, MVM_repr_box_int(tc,
                                tc->instance->boot_types.BOOTInt,
                                MVM_io_socket_native_family(tc, info->ai_addr->sa_family)->runtime));

                            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                            memcpy(&address->body.storage, info->ai_addr, info->ai_addrlen);
                            MVM_repr_push_o(tc, address_info, (MVMObject *)address);

                            MVM_repr_push_o(tc, address_info, MVM_repr_box_int(tc,
                                tc->instance->boot_types.BOOTInt,
                                MVM_io_socket_native_family(tc, info->ai_family)->runtime));
                            MVM_repr_push_o(tc, address_info, MVM_repr_box_int(tc,
                                tc->instance->boot_types.BOOTInt,
                                MVM_io_socket_native_type(tc, info->ai_socktype)->runtime));
                            MVM_repr_push_o(tc, address_info, MVM_repr_box_int(tc,
                                tc->instance->boot_types.BOOTInt,
                                MVM_io_socket_native_protocol(tc, info->ai_protocol)->runtime));
                        });
                        MVM_repr_push_o(tc, arr, address_info);
                    });
                default:
                    break;
            }
        }

        MVM_free(hostname_cstr);
        freeaddrinfo(result);
        return arr;
    }
}
