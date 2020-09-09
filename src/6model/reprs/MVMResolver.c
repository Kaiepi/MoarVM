#include "moar.h"

/* This representation's function pointer table. */
static const MVMREPROps MVMResolver_this_repr;

/* Creates a new type object of this representation, and associates it with
 * the given HOW. */
static MVMObject * type_object_for(MVMThreadContext *tc, MVMObject *HOW) {
    MVMSTable *st = MVM_gc_allocate_stable(tc, &MVMResolver_this_repr, HOW);

    MVMROOT(tc, st, {
        MVMObject *obj = MVM_gc_allocate_type_object(tc, st);
        MVM_ASSIGN_REF(tc, &(st->header), st->WHAT, obj);
        st->size = sizeof(MVMResolver);
    });

    return st->WHAT;
}

/* Initializes the resolver. */
static void initialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data) {
#ifndef HAVE_WINDNS
    MVMResolverBody *body;
    ldns_status      status;

    body = (MVMResolverBody *)data;
    if ((status = ldns_resolver_new_frm_fp(&body->context, NULL)))
        MVM_exception_throw_adhoc(tc,
            "Error initializing a DNS resolver: %s",
            ldns_get_errorstr_by_id(status));
    else {
        /* We cannot configure EDNS fallbacks ourselves with WinDNS. This is
         * enabled by default there, so enable it here too: */
        ldns_resolver_set_fallback(body->context, 1);
    }
#endif
}

/* Copies the body of one object to another. */
static void copy_to(MVMThreadContext *tc, MVMSTable *st, void *src, MVMObject *dest_root, void *dest) {
    MVMResolverBody *src_body  = (MVMResolverBody *)src;
    MVMResolverBody *dest_body = (MVMResolverBody *)dest;
#ifdef HAVE_WINDNS
    if (src_body->name_servers) {
        dest_body->name_servers = MVM_malloc(sizeof(DNS_ADDR_ARRAY));
        memcpy(dest_body->name_servers, src_body->name_servers, sizeof(DNS_ADDR_ARRAY));
    }
#else
    if (!(dest_body->context = ldns_resolver_clone(src_body->context)))
        MVM_exception_throw_adhoc(tc,
            "Error copying a DNS resolver: %s",
            ldns_get_errorstr_by_id(LDNS_STATUS_MEM_ERR));
    else {
        size_t name_servers_size = src_body->name_servers_count * sizeof(MVMResolverIPAddress);
        dest_body->name_servers = MVM_malloc(name_servers_size);
        memcpy(dest_body->name_servers, src_body->name_servers, sizeof(name_servers_size));

        MVM_ASSIGN_REF(tc, &(dest_root->header), dest_body->buf_type, src_body->buf_type);
    }
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

/* Set the size of the STable. */
static void deserialize_stable_size(MVMThreadContext *tc, MVMSTable *st, MVMSerializationReader *reader) {
    st->size = sizeof(MVMResolver);
}

/* Called by the VM in order to free memory associated with this object. */
static void gc_free(MVMThreadContext *tc, MVMObject *obj) {
    MVMResolverBody *body = (MVMResolverBody *)obj;
#ifndef HAVE_WINDNS
    ldns_resolver_deep_free(body->context);
#endif
    if (body->name_servers)
        MVM_free(body->name_servers);
}

/* Composes the representation. */
static void compose(MVMThreadContext *tc, MVMSTable *st, MVMObject *info) {
    /* Nothing doing. */
}

static MVMuint64 unmanaged_size(MVMThreadContext *tc, MVMSTable *st, void *data) {
    MVMResolverBody *body = (MVMResolverBody *)data;
#ifdef HAVE_WINDNS
    MVMuint64        size = 0;
    if (body->name_servers)
        size += sizeof(DNS_ADDR_ARRAY) + body->name_servers->AddrCount * sizeof(DNS_ADDR);
    return size;
#else
    return sizeof(ldns_resolver) +
           body->name_servers_count * sizeof(MVMResolverIPAddress);
#endif
}

static void describe_refs(MVMThreadContext *tc, MVMHeapSnapshotState *ss, MVMSTable *st, void *data) {
    static MVMuint64 buf_type_cache = 0;

    MVMResolverBody *body = (MVMResolverBody *)data;
    MVM_profile_heap_add_collectable_rel_const_cstr_cached(tc, ss,
        (MVMCollectable *)body->buf_type, "Buffer type", &buf_type_cache);
}

const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc) {
    return &MVMResolver_this_repr;
}

static const MVMREPROps MVMResolver_this_repr = {
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
    deserialize_stable_size,
    NULL, /* gc_mark */
    gc_free,
    NULL, /* gc_cleanup */
    NULL, /* gc_mark_repr_data */
    NULL, /* gc_free_repr_data */
    compose,
    NULL, /* spesh */
    "MVMResolver", /* name */
    MVM_REPR_ID_MVMResolver,
    unmanaged_size,
    describe_refs,
};

/* Prepares a DNS resolver for querying. This must only ever get called once
 * for any resolver because queries are very time-sensitive, which means we
 * can't afford to be doing any kind of synchronization we don't absolutely
 * need. Encourage modifying resolver configurations by configuring clones
 * instead. */
void MVM_resolver_configure(MVMThreadContext *tc, MVMResolver *resolver,
        MVMArray *name_servers, MVMuint16 default_port, MVMint64 tcp_only,
        MVMObject *buf_type) {
    size_t      i;
#ifndef HAVE_WINDNS
    size_t      name_servers_count;
    ldns_status status;
#endif

    /* Finish validating our objects: */
    if (STABLE(name_servers) != STABLE(tc->instance->boot_types.BOOTArray))
        MVM_exception_throw_adhoc(tc,
            "dnsconfigure name servers list must be an array of concrete IP addresses");
    for (i = 0; i < name_servers->body.elems; ++i) {
        MVMObject *maybe_address = name_servers->body.slots.o[i];
        if (REPR(maybe_address)->ID != MVM_REPR_ID_MVMAddress || !IS_CONCRETE(maybe_address))
            MVM_exception_throw_adhoc(tc,
                "dnsconfigure name servers list must be an array of concrete IP addresses");
        else switch (((MVMAddress *)maybe_address)->body.storage.any.sa_family) {
            case AF_INET:
            case AF_INET6:
                break;
            default:
                MVM_exception_throw_adhoc(tc,
                    "dnsconfigure name servers list must be an array of concrete IP addresses");
        }
    }

    if (MVM_cas(&resolver->body.configured, 0, 1))
        MVM_exception_throw_adhoc(tc, "DNS resolvers cannot be reconfigured");

#ifdef HAVE_WINDNS
    if (name_servers->body.elems) {
        size_t          i;
        PDNS_ADDR_ARRAY windns_name_servers;

        windns_name_servers           = resolver->body.name_servers = MVM_calloc(1, sizeof(DNS_ADDR_ARRAY));
        windns_name_servers->MaxCount = windns_name_servers->AddrCount = name_servers->body.elems;
        for (i = 0; i < name_servers->body.elems; ++i) {
            MVMAddress           *address;
            socklen_t             native_address_len;
            MVMResolverIPAddress  native_address;

            address            = (MVMAddress *)name_servers->body.slots.o[i];
            native_address_len = MVM_address_get_storage_length(tc, &address->body.storage.any);
            memcpy(&native_address, &address->body.storage, native_address_len);
            if (native_address.any.sa_family == AF_INET6)
                native_address.ip6.sin6_port = native_address.ip6.sin6_port || default_port;
            else
                native_address.ip4.sin_port = native_address.ip4.sin_port || default_port;
            memcpy(windns_name_servers->AddrArray + i, &native_address, native_address_len);
        }
    }

    resolver->body.query_flags = DNS_QUERY_WIRE_ONLY | DNS_QUERY_DISABLE_IDN_ENCODING;
    if (tcp_only)
        resolver->body.query_flags |= DNS_QUERY_USE_TCP_ONLY;
#else
    /* Set our resolver's name servers list: */
    if ((name_servers_count = name_servers->body.elems)) {
        size_t name_servers_size;

        name_servers_size           = name_servers_count * sizeof(MVMResolverIPAddress);
        resolver->body.name_servers = MVM_malloc(name_servers_size);
        for (i = 0; i < name_servers_count; ++i) {
            MVMAddress            *address            = (MVMAddress *)name_servers->body.slots.o[i];
            const struct sockaddr *native_address     = &address->body.storage.any;
            size_t                 native_address_len = MVM_address_get_storage_length(tc, native_address);
            memcpy(&resolver->body.name_servers[i], native_address, native_address_len);
        }
    }
    else if ((name_servers_count = ldns_resolver_nameserver_count(resolver->body.context))) {
        ldns_rdf **name_servers_ldns;

        /* Use the platform's configuration for DNS (as determined by LDNS): */
        name_servers_ldns           = ldns_resolver_nameservers(resolver->body.context);
        resolver->body.name_servers = MVM_malloc(name_servers_count * sizeof(MVMResolverIPAddress));
        for (i = 0; i < name_servers_count; ++i) {
            ldns_rdf                *address_ldns;
            size_t                   native_address_len;
            struct sockaddr_storage *native_address;

            address_ldns   = name_servers_ldns[i];
            native_address = ldns_rdf2native_sockaddr_storage(address_ldns, 0, &native_address_len);
            MVM_address_set_storage_length(tc, (struct sockaddr *)native_address, native_address_len);
            memcpy(&resolver->body.name_servers[i], native_address, native_address_len);
            MVM_free(native_address);
        }
    }
    resolver->body.name_servers_count = name_servers_count;

    /* Set our resolver context's default port: */
    if (default_port)
        ldns_resolver_set_port(resolver->body.context, default_port);

    /* Set our resolver context's fallback method configuration: */
    if (tcp_only) {
        ldns_resolver_set_fallback(resolver->body.context, 0);
        ldns_resolver_set_usevc(resolver->body.context, 1);
    }
    else {
        ldns_resolver_set_fallback(resolver->body.context, 1);
        ldns_resolver_set_usevc(resolver->body.context, 0);
    }
#endif /* HAVE_WINDNS */

    /* Set our resolver's buffer type: */
    MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.buf_type, buf_type);
}
