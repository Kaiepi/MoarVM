#include "moar.h"

MVM_STATIC_INLINE void memcpy_swap(void *dst, const void *src, const size_t elems, const size_t size) {
#ifdef MVM_BIGENDIAN
    memcpy(dst, src, size * elems);
#else
    size_t i, l, r;
    for (i = 0; i < elems; ++i)
        for (l = i * size, r = l + size; l < r--; ++l) {
            ((char *)dst)[l] = ((const char *)src)[r];
            ((char *)dst)[r] = ((const char *)src)[l];
        }
#endif
}

/* This representation's function pointer table. */
static const MVMREPROps MVMAddress_this_repr;

/* Creates a new type object of this representation and associates it with
 * the given HOW. */
static MVMObject * type_object_for(MVMThreadContext *tc, MVMObject *HOW) {
    MVMSTable *st = MVM_gc_allocate_stable(tc, &MVMAddress_this_repr, HOW);

    MVMROOT(tc, st, {
        MVMObject *obj = MVM_gc_allocate_type_object(tc, st);
        MVM_ASSIGN_REF(tc, &st->header, st->WHAT, obj);
        st->size = sizeof(MVMAddress);
    });

    return st->WHAT;
}

/* Initializes the address. */
static void initialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data) {
    /* Nothing doing. */
}

/* Copies the body of one object to another. */
static void copy_to(MVMThreadContext *tc, MVMSTable *st, void *src, MVMObject *dst_root, void *dst) {
    MVMAddressBody *src_body = (MVMAddressBody *)src;
    MVMAddressBody *dst_body = (MVMAddressBody *)dst;
    socklen_t       len      = MVM_address_get_length(src_body);
    memcpy(&dst_body->storage, &src_body->storage, len);
#ifndef MVM_HAS_SA_LEN
    MVM_address_set_length(dst_body, len);
#endif
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
    MVMint64        family = MVM_address_get_family(body);
    MVM_serialization_write_int(tc, writer, family);
    switch (family) {
        case AF_INET: {
            struct sockaddr_in *socket_address = &body->storage.sin;
            MVM_serialization_write_int(tc, writer, ntohl(socket_address->sin_addr.s_addr));
            MVM_serialization_write_int(tc, writer, ntohs(socket_address->sin_port));
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *socket_address;
            MVMuint32           *native_address;
            size_t               i;

#define NA_SIZE  sizeof(*native_address)
#define NA_ELEMS sizeof(socket_address->sin6_addr.s6_addr) / NA_SIZE
            socket_address = &body->storage.sin6;
#ifdef MVM_BIGENDIAN
            native_address = (MVMuint32 *)socket_address->sin6_addr.s6_addr;
#else
            native_address = (MVMuint32 [NA_ELEMS]){ };
            memcpy_swap(native_address, socket_address->sin6_addr.s6_addr, NA_ELEMS, NA_SIZE);
#endif
            for (i = 0; i < NA_ELEMS; ++i)
                MVM_serialization_write_int(tc, writer, native_address[i]);
            MVM_serialization_write_int(tc, writer, socket_address->sin6_port);
            MVM_serialization_write_int(tc, writer, socket_address->sin6_scope_id);
            break;
#undef NA_ELEMS
#undef NA_SIZE
        }
#ifdef MVM_HAS_PF_UNIX
        case AF_UNIX: {
            struct sockaddr_un *socket_address = &body->storage.sun;
            socklen_t           len            = MVM_address_get_length(body);
            MVM_serialization_write_ptr(tc, writer, socket_address->sun_path,
                sizeof(*socket_address) - sizeof(socket_address->sun_path) + len);
            break;
        }
#endif
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported native socket family: %hu", (MVMuint16)family);
    }
}

/* Deserializes the data. */
static void deserialize(MVMThreadContext *tc,
        MVMSTable *st, MVMObject *root, void *data, MVMSerializationReader *reader) {
    MVMAddressBody *body   = (MVMAddressBody *)data;
    MVMint64        family = MVM_serialization_read_int(tc, reader);
    switch (family) {
        case AF_INET: {
            struct sockaddr_in socket_address;
            memset(&socket_address, 0, sizeof(socket_address)),
            socket_address.sin_family      = family;
            socket_address.sin_addr.s_addr = htonl(MVM_serialization_read_int(tc, reader));
            socket_address.sin_port        = htons(MVM_serialization_read_int(tc, reader));
            memcpy(&body->storage, &socket_address, sizeof(socket_address));
            MVM_address_set_length(body, sizeof(socket_address));
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6  socket_address;
            MVMuint32           *native_address;
            size_t               i;

#define NA_SIZE  sizeof(*native_address)
#define NA_ELEMS sizeof(socket_address.sin6_addr.s6_addr) / NA_SIZE
            memset(&socket_address, 0, sizeof(socket_address));
#ifdef MVM_BIGENDIAN
            native_address = socket_address->sin6_addr.s6_addr;
            for (i = 0; i < NA_ELEMS; ++i)
                native_address[i] = (MVMuint32)MVM_serialization_read_int(tc, reader);
#else
            native_address = (MVMuint32 [NA_ELEMS]){ };
            for (i = 0; i < NA_ELEMS; ++i)
                native_address[i] = (MVMuint32)MVM_serialization_read_int(tc, reader);
            memcpy_swap(socket_address.sin6_addr.s6_addr, native_address, NA_ELEMS, NA_SIZE);
#endif
            socket_address.sin6_port     = (MVMuint32)MVM_serialization_read_int(tc, reader);
            socket_address.sin6_scope_id = (MVMuint32)MVM_serialization_read_int(tc, reader);
            memcpy(&body->storage, &socket_address, sizeof(socket_address));
            MVM_address_set_length(body, sizeof(socket_address));
            break;
#undef NA_ELEMS
#undef NA_SIZE
        }
#ifdef MVM_HAS_PF_UNIX
        case AF_UNIX: {
            struct sockaddr_un  socket_address;
            char               *path;
            size_t              path_len;

            memset(&socket_address, 0, sizeof(socket_address));
            socket_address.sun_family = family;
            path                      = MVM_serialization_read_ptr(tc, reader, &path_len);
            memcpy(socket_address.sun_path, path, path_len);
            memcpy(&body->storage, &socket_address, sizeof(socket_address));
            MVM_address_set_length(body, sizeof(socket_address) - sizeof(socket_address.sun_path) + path_len);
            MVM_free(path);
            break;
        }
#endif
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported native socket family: %hhu", family);
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
