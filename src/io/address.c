#include "moar.h"

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
