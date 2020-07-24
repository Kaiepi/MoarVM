#include "moar.h"

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
    memcpy(&dest_body->storage, &src_body->storage, MVM_address_get_storage_length(tc, &dest_body->storage.any));
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

/* Serializes the data. */
static void serialize(MVMThreadContext *tc, MVMSTable *st, void *data, MVMSerializationWriter *writer) {
    MVMAddressBody *body   = (MVMAddressBody *)data;
    sa_family_t     family = body->storage.any.sa_family;
    MVM_serialization_write_int(tc, writer, family);
    switch (family) {
        case AF_INET: {
            struct sockaddr_in *socket_address = &body->storage.ip4;
            MVM_serialization_write_int(tc, writer, socket_address->sin_addr.s_addr);
            MVM_serialization_write_int(tc, writer, socket_address->sin_port);
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *socket_address;
            size_t               i;

            socket_address = &body->storage.ip6;
            for (i = 0; i < 4; ++i) {
                MVMuint32 dword;
                size_t    j;

                dword = 0;
                for (j = 0; j < 4; ++j)
                    dword = (dword << 8) | socket_address->sin6_addr.s6_addr[i * 4 + j];
                MVM_serialization_write_int(tc, writer, dword);
            }
            MVM_serialization_write_int(tc, writer, socket_address->sin6_port);
            MVM_serialization_write_int(tc, writer, socket_address->sin6_scope_id);
            break;
        }
        case AF_UNIX: {
#ifdef MVM_HAS_AF_UNIX
            struct sockaddr_un *socket_address = &body->storage.un;
            MVM_serialization_write_array(tc, writer, socket_address->sun_path,
                MVM_address_get_storage_length(tc, (struct sockaddr *)socket_address));
#else
            MVM_exception_throw_adhoc(tc, "UNIX sockets are not supported by MoarVM on this platform");
#endif
            break;
        }
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported native socket family: %hhu", body->storage.any.sa_family);
            break;
    }
}

/* Deserializes the data. */
static void deserialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data, MVMSerializationReader *reader) {
    MVMAddressBody *body    = (MVMAddressBody *)data;
    sa_family_t     family  = (sa_family_t)MVM_serialization_read_int(tc, reader);
    switch (family) {
        case AF_INET: {
            struct sockaddr_in socket_address;

            memset(&socket_address, 0, sizeof(socket_address));
            MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, sizeof(socket_address));
            socket_address.sin_family      = family;
            socket_address.sin_addr.s_addr = (in_addr_t)MVM_serialization_read_int(tc, reader);
            socket_address.sin_port        = (in_port_t)MVM_serialization_read_int(tc, reader);
            memcpy(&body->storage, &socket_address, sizeof(socket_address));
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 socket_address;
            size_t              i;

            memset(&socket_address, 0, sizeof(socket_address));
            MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, sizeof(socket_address));
            socket_address.sin6_family = family;
            for (i = 0; i < 4; ++i) {
                MVMuint32 dword;
                size_t    j;

                dword = (MVMuint32)MVM_serialization_read_int(tc, reader);
                for (j = 0; j < 4; ++j)
                    socket_address.sin6_addr.s6_addr[i * 4 + j] = (dword >> (3 - j) * 8) & 0xFF;
            }
            socket_address.sin6_scope_id = (MVMuint32)MVM_serialization_read_int(tc, reader);
            memcpy(&body->storage, &socket_address, sizeof(socket_address));
            break;
        }
        case AF_UNIX: {
#ifdef MVM_HAS_AF_UNIX
            char               *path;
            size_t              path_size;
            struct sockaddr_un  socket_address;
            socklen_t           socket_address_len;

            path               = MVM_serialization_read_array(tc, reader, &path_size);
            socket_address_len = sizeof(socket_address) - sizeof(socket_address.sun_path) + path_size;
            memset(&socket_address, 0, sizeof(socket_address));
            MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, socket_address_len);
            socket_address.sun_family = family;
            memcpy(socket_address.sun_path, path, path_size);
            memcpy(&body->storage, &socket_address, socket_address_len);
            MVM_free(path);
            break;
#else
            MVM_exception_throw_adhoc(tc, "UNIX sockets are not supported by MoarVM on this platform");
#endif
        }
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported native socket family: %hhu", family);
            break;
    }
}

/* Sets the size of the STable. */
static void deserialize_stable_size(MVMThreadContext *tc, MVMSTable *st, MVMSerializationReader *reader) {
    st->size = sizeof(MVMAddress);
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
    serialize,
    deserialize,
    NULL, /* serialize_repr_data */
    NULL, /* deserialize_repr_data */
    deserialize_stable_size,
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

MVMuint16 MVM_address_get_port(MVMThreadContext *tc, MVMAddress *address) {
    switch (address->body.storage.any.sa_family) {
        case AF_INET:
            return ntohs(address->body.storage.ip4.sin_port);
        case AF_INET6:
            return ntohs(address->body.storage.ip6.sin6_port);
        default:
            MVM_exception_throw_adhoc(tc, "Can only get the port of an IP address");
    }
}

MVMuint32 MVM_address_get_scope_id(MVMThreadContext *tc, MVMAddress *address) {
    if (address->body.storage.any.sa_family == AF_INET6)
        /* Scope IDs are not stored in network byte order. */
        return address->body.storage.ip6.sin6_scope_id;
    else
        MVM_exception_throw_adhoc(tc, "Can only get the scope ID of an IPv6 address");
}

MVMObject * MVM_address_from_ipv4_literal(MVMThreadContext *tc, MVMString *literal, MVMuint16 port) {
    char               *literal_cstr;
    struct sockaddr_in  socket_address;
    int                 error;

    literal_cstr = MVM_string_utf8_encode_C_string(tc, literal);
    error        = uv_ip4_addr(literal_cstr, port, &socket_address);
    MVM_free(literal_cstr);

    if (error)
        MVM_exception_throw_adhoc(tc,
            "Error creating an IPv4 address from a literal: %s",
            uv_strerror(error));
    else {
        MVMAddress* address;
        MVMROOT(tc, literal, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, sizeof(struct sockaddr_in));
        });
        return (MVMObject *)address;
    }
}

MVMObject * MVM_address_from_ipv6_literal(MVMThreadContext *tc, MVMString *literal, MVMuint16 port) {
    char                *literal_cstr;
    struct sockaddr_in6  socket_address;
    int                  error;

    literal_cstr = MVM_string_utf8_encode_C_string(tc, literal);
    error        = uv_ip6_addr(literal_cstr, port, &socket_address);
    MVM_free(literal_cstr);

    if (error)
        MVM_exception_throw_adhoc(tc,
            "Error creating an IPv6 address from a literal: %s",
            uv_strerror(error));
    else {
        MVMAddress* address;
        MVMROOT(tc, literal, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, &socket_address, sizeof(socket_address));
        });
        return (MVMObject *)address;
    }
}

MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path) {
#ifdef MVM_HAS_AF_UNIX
    MVMuint64  path_len;
    char      *path_cstr;

    path_cstr = MVM_string_utf8_encode(tc, path, &path_len, 0);
    if (path_len >= MVM_SOCKADDR_UN_PATH_SIZE) {
        MVM_free(path_cstr);
        MVM_exception_throw_adhoc(tc,
            "UNIX socket address path is too long (max length supported by this platform is %zu characters)",
            MVM_SOCKADDR_UN_PATH_SIZE - 1);
    }
    else {
        struct sockaddr_un *socket_address;
        MVMAddress         *address;

        MVMROOT(tc, path, {
            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
        });
        MVM_address_set_storage_length(tc, &address->body.storage.any,
            sizeof(*socket_address) - MVM_SOCKADDR_UN_PATH_SIZE + path_len);
        socket_address             = &address->body.storage.un;
        socket_address->sun_family = AF_UNIX;
        memcpy(socket_address->sun_path, path_cstr, path_len * sizeof(char));
        MVM_free(path_cstr);
        return (MVMObject *)address;
    }
#else
    MVM_exception_throw_adhoc(tc, "UNIX sockets are not supported by MoarVM on this platform");
#endif
}

MVMString * MVM_address_to_string(MVMThreadContext *tc, MVMAddress *address) {
    MVMString *address_str;

    switch (address->body.storage.any.sa_family) {
        case AF_INET: {
            char address_cstr[INET_ADDRSTRLEN];
            int  error;

            if ((error = uv_ip4_name(&address->body.storage.ip4, address_cstr, sizeof(address_cstr))))
                MVM_exception_throw_adhoc(tc,
                    "Error creating an IPv4 address literal: %s",
                    strerror(errno));
            else {
                size_t address_cstr_len = strnlen(address_cstr, sizeof(address_cstr) - 1);
                MVMROOT(tc, address, {
                    address_str = MVM_string_utf8_decode(tc, tc->instance->VMString, address_cstr, address_cstr_len);
                });
            }
            break;
        }
        case AF_INET6: {
            char address_cstr[INET6_ADDRSTRLEN + 1 + UV_IF_NAMESIZE];
            int  error;

            if ((error = uv_ip6_name(&address->body.storage.ip6, address_cstr, INET6_ADDRSTRLEN)))
                MVM_exception_throw_adhoc(tc,
                    "Error creating an IPv6 address literal: %s",
                    strerror(errno));
            else {
                size_t    address_len;
                MVMuint32 address_scope_id;

                address_len = strnlen(address_cstr, INET6_ADDRSTRLEN);
                if ((address_scope_id = address->body.storage.ip6.sin6_scope_id)) {
                    size_t presentation_len = address_len;
                    size_t interface_len    = UV_IF_NAMESIZE;
                    address_cstr[presentation_len] = '%';
                    if ((error = uv_if_indextoiid(address_scope_id, address_cstr + presentation_len + 1, &interface_len)))
                        MVM_exception_throw_adhoc(tc,
                            "Error creating an IPv6 address literal: %s",
                            uv_strerror(error));
                    else
                        address_len += 1 + interface_len;
                }

                MVMROOT(tc, address, {
                    address_str = MVM_string_utf8_decode(tc, tc->instance->VMString, address_cstr, address_len);
                });
            }
            break;
        }
#ifdef MVM_HAS_AF_UNIX
        case AF_UNIX: {
            MVMROOT(tc, address, {
                const char *path_cstr = address->body.storage.un.sun_path;
                size_t      path_len  = MVM_SOCKADDR_UN_PATH_SIZE -
                                        sizeof(struct sockaddr_un) +
                                        MVM_address_get_storage_length(tc, &address->body.storage.any);
                address_str = MVM_string_utf8_c8_decode(tc, tc->instance->VMString, path_cstr, path_len);
            });
            break;
        }
#endif
        default:
            MVM_exception_throw_adhoc(tc,
                "Unknown native address family: %hhu",
                address->body.storage.any.sa_family);
            break;
    }

    return address_str;
}
