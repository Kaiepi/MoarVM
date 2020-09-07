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
#ifdef HAVE_WINDNS
    /* TODO */
#else
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
        ldns_resolver_set_edns_udp_size(body->context, 4096);
    }
#endif
}

/* Copies the body of one object to another. */
static void copy_to(MVMThreadContext *tc, MVMSTable *st, void *src, MVMObject *dest_root, void *dest) {
#ifdef HAVE_WINDNS
    /* TODO */
#else
    MVMResolverBody *src_body  = (MVMResolverBody *)src;
    MVMResolverBody *dest_body = (MVMResolverBody *)dest;
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
#ifdef HAVE_WINDNS
    /* TODO */
#else
    MVMResolverBody *body = (MVMResolverBody *)obj;
    ldns_resolver_deep_free(body->context);
    if (body->name_servers)
        MVM_free(body->name_servers);
#endif
}

/* Composes the representation. */
static void compose(MVMThreadContext *tc, MVMSTable *st, MVMObject *info) {
    /* Nothing doing. */
}

/* Initializes the representation. */
static MVMuint64 unmanaged_size(MVMThreadContext *tc, MVMSTable *st, void *data) {
#ifdef HAVE_WINDNS
    /* TODO */
    return 0;
#else
    MVMResolverBody *body = (MVMResolverBody *)data;
    return sizeof(ldns_resolver) +
           body->name_servers_count * sizeof(MVMResolverIPAddress);
#endif
}

static void describe_refs(MVMThreadContext *tc, MVMHeapSnapshotState *ss, MVMSTable *st, void *data) {
#ifdef HAVE_WINDNS
    /* TODO */
#else
    static MVMuint64 buf_type_cache = 0;

    MVMResolverBody *body = (MVMResolverBody *)data;
    MVM_profile_heap_add_collectable_rel_const_cstr_cached(tc, ss,
        (MVMCollectable *)body->buf_type, "Buffer type", &buf_type_cache);
#endif
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
        MVMArray *name_servers, MVMuint16 default_port,
        MVMObject *buf_type) {
#ifdef HAVE_WINDNS
    /* TODO */
#else /* HAVE_WINDNS */
    size_t      name_servers_count;
    size_t      i;
    ldns_status status;

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

    /* Set our resolver's name servers list: */
    if (name_servers_count) {
        size_t name_servers_size;

        name_servers_count          = name_servers->body.elems;
        name_servers_size           = name_servers_count * sizeof(MVMResolverIPAddress);
        resolver->body.name_servers = MVM_malloc(name_servers_size);
        for (i = 0; i < name_servers_count; ++i) {
            MVMAddress            *address            = (MVMAddress *)name_servers->body.slots.o[i];
            const struct sockaddr *native_address     = &address->body.storage.any;
            size_t                 native_address_len = MVM_address_get_storage_length(tc, native_address);
            memcpy(&resolver->body.name_servers[i], native_address, native_address_len);
        }
    }
    else {
        ldns_rdf **name_servers_ldns;

        /* Use the platform's configuration for DNS (as determined by LDNS): */
        name_servers_count = ldns_resolver_nameserver_count(resolver->body.context);
        if ((name_servers_ldns = ldns_resolver_nameservers(resolver->body.context))) {
            resolver->body.name_servers = MVM_malloc(name_servers_count * sizeof(MVMResolverIPAddress));
            for (i = 0; i < name_servers_count; ++i) {
                ldns_rdf                *address_ldns;
                size_t                   native_address_len;
                struct sockaddr_storage *native_address;

                address_ldns   = name_servers_ldns[i];
                native_address = ldns_rdf2native_sockaddr_storage(address_ldns, default_port,
                    &native_address_len);
                memcpy(&resolver->body.name_servers[i], native_address, native_address_len);
                MVM_free(native_address);
            }
        }
    }
    resolver->body.name_servers_count = name_servers_count;

    /* Set our resolver context's default port: */
    if (default_port)
        ldns_resolver_set_port(resolver->body.context, default_port);

    /* Set our resolver's buffer type: */
    MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.buf_type, buf_type);
#endif /* HAVE_WINDNS */
}
