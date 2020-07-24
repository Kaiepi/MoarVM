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
