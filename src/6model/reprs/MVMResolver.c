#include "moar.h"

#ifdef HAVE_WINDNS
#include <iphlpapi.h>
#endif

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
    /* Nothing doing. */
}

/* Copies the body of one object to another. */
static void copy_to(MVMThreadContext *tc, MVMSTable *st, void *src, MVMObject *dest_root, void *dest) {
    MVMResolverBody *src_body;
    MVMResolverBody *dest_body;
#ifdef HAVE_WINDNS
    size_t           i;
#endif

    src_body  = (MVMResolverBody *)src;
    dest_body = (MVMResolverBody *)dest;
#ifdef HAVE_WINDNS
    dest_body->servers      = MVM_calloc(src_body->server_count, sizeof(MVMAddress *));
    dest_body->server_count = src_body->server_count;
    for (i = 0; i < src_body->server_count; ++i)
        MVM_ASSIGN_REF(tc, &(dest_root->header), dest_body->servers[i], src_body->servers[i]);
    dest_body->default_port = src_body->default_port;
    dest_body->query_flags  = src_body->query_flags;
    MVM_ASSIGN_REF(tc, &(dest_root->header), dest_body->buf_type, src_body->buf_type);
#else
    if (!(dest_body->context = ldns_resolver_clone(src_body->context)))
        MVM_exception_throw_adhoc(tc,
            "Error copying a DNS resolver: %s",
            ldns_get_errorstr_by_id(LDNS_STATUS_MEM_ERR));
    else {
        size_t name_servers_size;

        name_servers_size = src_body->name_servers_count * sizeof(MVMResolverIPAddress);
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
#ifdef HAVE_WINDNS
    MVM_free(body->servers);
#else
    ldns_resolver_deep_free(body->context);
    MVM_free(body->name_servers);
#endif
}

/* Composes the representation. */
static void compose(MVMThreadContext *tc, MVMSTable *st, MVMObject *info) {
    /* Nothing doing. */
}

static MVMuint64 unmanaged_size(MVMThreadContext *tc, MVMSTable *st, void *data) {
    MVMResolverBody *body = (MVMResolverBody *)data;
#ifdef HAVE_WINDNS
    return body->server_count * sizeof(MVMAddress *);
#else
    return sizeof(ldns_resolver) +
           body->name_servers_count * sizeof(MVMResolverIPAddress);
#endif
}

#if 0
static void describe_refs(MVMThreadContext *tc, MVMHeapSnapshotState *ss, MVMSTable *st, void *data) {
    static MVMuint64 buf_type_cache = 0;

    MVMResolverBody *body;
#ifdef HAVE_WINDNS
    MVMuint64 server_cache;
    size_t    i;
#endif

    body = (MVMResolverBody *)data;
#ifdef HAVE_WINDNS
    server_cache = 0;
    for (i = 0; i < body->server_count; ++i)
        MVM_profile_heap_add_collectable_rel_const_cstr_cached(tc, ss,
            (MVMCollectable *)body->servers[i], "DNS server address", &server_cache);
#endif

    MVM_profile_heap_add_collectable_rel_const_cstr_cached(tc, ss,
        (MVMCollectable *)body->buf_type, "Buffer type", &buf_type_cache);
}
#endif

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
/*  describe_refs, */
    NULL,
};

/* Prepares a DNS resolver for querying. This must only ever get called once
 * for any resolver because queries are very time-sensitive, which means we
 * can't afford to be doing any kind of synchronization we don't absolutely
 * need. Encourage modifying resolver configurations by configuring clones
 * instead. */
void MVM_resolver_configure(MVMThreadContext *tc, MVMResolver *resolver,
        MVMArray *servers, MVMuint16 default_port, MVMint64 tcp_only,
        MVMObject *buf_type) {
    size_t      i;
    size_t      server_count;
#ifdef HAVE_WINDNS
    int         error;
#else
    ldns_status status;
#endif

    /* Finish validating our objects: */
    if (STABLE(servers) != STABLE(tc->instance->boot_types.BOOTArray))
        MVM_exception_throw_adhoc(tc,
            "dnsconfigure servers list must be an array of concrete IP addresses");
    else for (i = 0; i < servers->body.elems; ++i) {
        MVMObject *maybe_address = servers->body.slots.o[i];
        if (REPR(maybe_address)->ID != MVM_REPR_ID_MVMAddress || !IS_CONCRETE(maybe_address))
            MVM_exception_throw_adhoc(tc,
                "dnsconfigure servers list must be an array of concrete IP addresses");
        else switch (((MVMAddress *)maybe_address)->body.storage.any.sa_family) {
            case AF_INET:
            case AF_INET6:
                break;
            default:
                MVM_exception_throw_adhoc(tc,
                    "dnsconfigure servers list must be an array of concrete IP addresses");
        }
    }

    if (MVM_cas(&resolver->body.configured, 0, 1))
        MVM_exception_throw_adhoc(tc, "DNS resolvers cannot be reconfigured");

#ifdef HAVE_WINDNS
    /* Set our resolver's name servers list: */
    if ((server_count = servers->body.elems)) {
        resolver->body.servers      = MVM_calloc(server_count, sizeof(MVMAddress *));
        resolver->body.server_count = server_count;
        for (i = 0; i < server_count; ++i)
            MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.servers[i], servers->body.slots.o[i]);
    }
    else {
        MVMuint32                      adapters_size;
        PIP_ADAPTER_ADDRESSES          adapters, adapter;
        PIP_ADAPTER_DNS_SERVER_ADDRESS server;
        int                            error;

        /* Get the system's list of network adapters. The API for this is
           pretty silly; we're expected to know how much memory should be
           allocated for this (which we can get by passing too small a size
           to GetAdaptersAddresses), but this can change between calls.
           We'll give the OS 3 chances to give us the adapters list before
           giving up: */
        adapters_size = 15360; /* 15KB, as recommended by MS' docs for GetAdapterAddresses. */
        adapters      = MVM_malloc(adapters_size);
        for (i = 3; i--;) {
            char *errstr_cstr;

            if (!(error = GetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME,
                    NULL, adapters, &adapters_size)))
                break;
            else if (i && error == ERROR_BUFFER_OVERFLOW)
                adapters = MVM_realloc(adapters, adapters_size);
            else if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPSTR)&errstr_cstr, 0, NULL)) {
                char *waste[] = { errstr_cstr, NULL };
                MVM_free(adapters);
                MVM_exception_throw_adhoc_free(tc, waste, "Error configuring a DNS resolver: %s", errstr_cstr);
            }
            else {
                errstr_cstr = strerror(GetLastError());
                MVM_exception_throw_adhoc(tc, "Error configuring a DNS resolver: %s", errstr_cstr);
            }
        }

        /* Get the number of configured DNS servers for network
           adapters that we can make connections from. How this is determined
           is cargo-culted from .NET's NetworkInterface.GetIsNetworkAvailable
           method: */
        server_count = 0;
        for (adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp)
                continue;
            else if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL)
                continue;
            else for (server = adapter->FirstDnsServerAddress; server; server = server->Next) {
                server_count++;
            }
        }
        if (!server_count)
            MVM_exception_throw_adhoc(tc, "No system configuration for DNS servers was found.");

        /* Copy our usable DNS server addresses: */
        /* printf("Found %zu DNS servers", server_count); */
        resolver->body.servers      = MVM_calloc(server_count, sizeof(MVMAddress *));
        resolver->body.server_count = server_count;
        for (adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp)
                continue;
            else if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL)
                continue;
            else for (server = adapter->FirstDnsServerAddress, i = 0; server; server = server->Next, ++i) {
                MVMAddress *address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                memcpy(&address->body.storage, server->Address.lpSockaddr, server->Address.iSockaddrLength);
                MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.servers[i], address);
            }
        }

        MVM_free(adapters);
    }

    /* Set our resolver's default port: */
    resolver->body.default_port = default_port;

    /* Set our resolver's DNSQueryEx flags: */
    resolver->body.query_flags =
        DNS_QUERY_NO_NETBT |            /* Disable NetBIOS over TCP/IP. */
        DNS_QUERY_WIRE_ONLY |           /* Disable caching, hosts file handling, and local name handling. */
        DNS_QUERY_RETURN_MESSAGE |      /* Get the entire response. */
        DNS_QUERY_NO_MULTICAST |        /* Disable LLMNR. */
        DNS_QUERY_TREAT_AS_FQDN |       /* Disable domain name searching. */
        DNS_QUERY_DISABLE_IDN_ENCODING; /* Disable Punycode handling. */
    if (tcp_only)
        resolver->body.query_flags |= DNS_QUERY_USE_TCP_ONLY;
#else /* HAVE_WINDNS */
    /* Set up our resolution context: */
    if ((status = ldns_resolver_new_frm_fp(&body->context, NULL)))
        MVM_exception_throw_adhoc(tc,
            "Error initializing a DNS resolver: %s",
            ldns_get_errorstr_by_id(status));

    /* Set our resolver's name servers list: */
    if ((server_count = servers->body.elems)) {
        resolver->body.servers      = MVM_calloc(server_count, sizeof(MVMAddress *));
        resolver->body.server_count = server_count;
        for (i = 0; i < server_count; ++i)
            MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.servers[i], servers->body.slots.o[i]);
    }
    else if ((server_count = ldns_resolver_nameserver_count(resolver->body.context))) {
        const ldns_rdf **default_servers;

        /* Use the platform's configuration for DNS (as determined by LDNS): */
        resolver->body.servers      = MVM_calloc(server_count + 1, sizeof(MVMAddress *));
        resolver->body.server_count = server_count;
        default_servers             = ldns_resolver_nameservers(resolver->body.context);
        for (i = 0; i < server_count; ++i) {
            const ldns_rdf                *server;
            size_t                         native_address_len;
            const struct sockaddr_storage *native_address;
            MVMAddress                    *address;

            server         = default_servers[i];
            native_address = ldns_rdf2native_sockaddr_storage(address_ldns, 0, &native_address_len);
            MVM_address_set_storage_length(tc, (struct sockaddr *)native_address, native_address_len);

            address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
            memcpy(&address->body.storage, native_address, native_address_len);
            MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.servers[i], address);
        }
    }
    else
        MVM_exception_throw_adhoc(tc, "No system configuration for DNS servers was found.");

    /* Set our resolver context's default port: */
    if (default_port)
        ldns_resolver_set_port(resolver->body.context, default_port);

    /* Set our resolver context's transports: */
    ldns_resolver_set_fallback(resolver->body.context, !tcp_only);
    ldns_resolver_set_usevc(resolver->body.context, !!tcp_only);
#endif /* HAVE_WINDNS */

    /* Set our resolver's buffer type: */
    MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.buf_type, buf_type);
}
