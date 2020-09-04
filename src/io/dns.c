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

MVMObject * MVM_io_dns_create_resolver(MVMThreadContext *tc,
        MVMArray *name_servers, MVMuint16 default_port,
        MVMObject *buf_type) {
#ifdef HAVE_WINDNS
    /* TODO */
#else /* HAVE_WINDNS */
    MVMResolver *resolver;
    size_t       i;
    ldns_status  error;

    /* Validate our types: */
    if (STABLE(name_servers) != STABLE(tc->instance->boot_types.BOOTArray))
        MVM_exception_throw_adhoc(tc,
            "dnsresolver name servers list must be an array of IP addresses");
    for (i = 0; i < name_servers->body.elems; ++i)
        if (REPR(name_servers->body.slots.o[i])->ID != MVM_REPR_ID_MVMAddress)
            MVM_exception_throw_adhoc(tc,
                "dnsresolver name servers list must be an array of IP addresses");

    /* Allocate our DNS resolver: */
    error    = LDNS_STATUS_OK;
    resolver = (MVMResolver *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTResolver);
    if ((error = ldns_resolver_new_frm_fp(&resolver->body.context, NULL)))
        goto error;

    /* Set our context's name servers: */
    if (name_servers->body.elems) {
        ldns_rdf *ldns_name_servers[name_servers->body.elems + 1];

        for (i = 0; i < name_servers->body.elems; ++i) {
            MVMAddress      *address;
            struct sockaddr *native_address;
            socklen_t        native_address_len;
            ldns_rdf        *ldns_address;

            address            = (MVMAddress *)name_servers->body.slots.o[i];
            native_address     = &address->body.storage.any;
            native_address_len = MVM_address_get_storage_length(tc, native_address);
            switch (native_address->sa_family) {
                case AF_INET:
                    ldns_address = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, native_address_len, native_address);
                    break;
                case AF_INET6:
                    ldns_address = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, native_address_len, native_address);
                    break;
                default:
                    error = LDNS_STATUS_UNKNOWN_INET;
                    goto error;
            }

            if (ldns_address)
                ldns_name_servers[i] = ldns_address;
            else {
                error = LDNS_STATUS_MEM_ERR;
                goto error;
            }
        }
        ldns_name_servers[i] = NULL;

        ldns_resolver_set_nameservers(resolver->body.context, ldns_name_servers);
    }

    /* Set our context's default port: */
    if (default_port)
        ldns_resolver_set_port(resolver->body.context, default_port);

    /* Back to the resolver itself, set up its query buffer type: */
    MVM_ASSIGN_REF(tc, &(resolver->common.header), resolver->body.buf_type, buf_type);
    return (MVMObject *)resolver;

error:
    assert(error != LDNS_STATUS_OK);
    MVM_exception_throw_adhoc(tc,
        "Error creating a DNS resolution context: %s",
        ldns_get_errorstr_by_id(error));
#endif /* HAVE_WINDNS */
}

#ifdef HAVE_WINDNS
/* TODO */
#else /* HAVE_WINDNS */
typedef struct {
    MVMResolver   *resolver;
    MVMString     *domain_name;
    ldns_rr_type   type;
    ldns_rr_class  class;

    MVMThreadContext *tc;
    uv_loop_t        *loop;
    int               work_idx;
    ldns_buffer      *question;
    size_t            name_server_idx;
    size_t            name_server_end;
    uv_poll_t        *handle;
    ldns_pkt_rcode    error;
} QueryInfo;

/* LDNS does not provide an asynchronous API for making queries. It can be made
 * to work with libuv asynchronously through its ldns_udp_bgsend and
 * ldns_tcp_bgsend functions, but these are rather low-level and there is extra
 * work involved in using these to handle queries... */

/* Sends a query to a nameserver. The sending functions used yield a file
 * descriptor, which may be polled: */
static void query_init(QueryInfo *qi);
/* Reads from the query's socket. If successful, processes the response
 * received. If truncated, repeat over TCP. If this isn't the case for an
 * unsuccessful query, then if there are nameservers left to use, begins a
 * query with the next one, otherwise completes the query's task with no
 * response. */
static void query_poll(uv_poll_t *handle, int status, int events);
/* Processes the response to a query and completes the task for it. */
static void query_process(QueryInfo *qi, MVMuint8 *wire, size_t wire_size);

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMAsyncTask *task;
    QueryInfo    *qi;
    char         *domain_name_cstr;
    ldns_rdf     *domain_name;
    ldns_pkt     *packet;
    ldns_status   error;

    /* Add to work in progress: */
    task                = (MVMAsyncTask *)async_task;
    qi                  = (QueryInfo *)data;
    qi->tc              = tc;
    qi->loop            = loop;
    qi->work_idx        = MVM_io_eventloop_add_active_work(tc, async_task);
    qi->name_server_end = ldns_resolver_nameserver_count(qi->resolver->body.context);

    /* Prepare to make the DNS query: */
    domain_name_cstr = MVM_string_ascii_encode(tc, qi->domain_name, NULL, 0);
    if ((error = ldns_str2rdf_dname(&domain_name, domain_name_cstr)))
        goto error;
    else if ((error = ldns_resolver_prepare_query_pkt(&packet, qi->resolver->body.context,
                 domain_name, qi->type, qi->class, LDNS_RD)))
        goto error;
    else if (!(qi->question = ldns_buffer_new(LDNS_MIN_BUFLEN)))
        goto merror;
    else if ((error = ldns_pkt2buffer_wire(qi->question, packet)))
        goto error;
    else {
        query_init(qi);
        goto cleanup;
    }

merror:
    error = LDNS_STATUS_MEM_ERR;
error:
    assert(error);
    MVMROOT(tc, task, {
        MVMObject *result;
        MVMString *errstr;

        result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVM_repr_push_o(tc, result, task->body.schedulee);

        /* Push the error message: */
        errstr = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, ldns_get_errorstr_by_id(error));
        MVM_repr_push_o(tc, result, MVM_repr_box_str(tc, tc->instance->boot_types.BOOTStr, errstr));

        MVM_repr_push_o(tc, task->body.queue, result);
    });

    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
cleanup:
    if (domain_name)
        ldns_rdf_deep_free(domain_name);
    if (domain_name_cstr)
        MVM_free(domain_name_cstr);
}

static void query_init(QueryInfo *qi) {
    /* Select the next name server to make a DNS query with: */
    MVMThreadContext *tc;
    MVMAsyncTask     *task;
    size_t            name_server_idx;
    int               error;
    ldns_status       status;
    const char       *errstr_cstr;

    tc              = qi->tc;
    task            = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    name_server_idx = qi->name_server_idx++;
    error           = 0;
    status          = LDNS_STATUS_OK;
    if (name_server_idx == qi->name_server_end)
        goto ldns_qerror;
    else {
        ldns_rdf                *ldns_address;
        size_t                   native_address_len;
        struct sockaddr_storage *native_address;
        struct timeval           timeout;
        int                      fd;

        ldns_address   = ldns_resolver_nameservers(qi->resolver->body.context)[name_server_idx];
        native_address = ldns_rdf2native_sockaddr_storage(ldns_address, 0, &native_address_len);
        memset(&timeout, 0, sizeof(timeout));

        fd = ldns_udp_bgsend(qi->question, native_address, native_address_len, timeout);
        if (fd < 0) {
            status = LDNS_STATUS_MEM_ERR;
            goto ldns_error;
        }
        else if (!qi->handle) {
            qi->handle       = MVM_malloc(sizeof(uv_handle_t));
            qi->handle->data = qi;
        }

        if ((error = uv_poll_init(qi->loop, qi->handle, fd)))
            goto uv_error;
        else if ((error = uv_poll_start(qi->handle, UV_READABLE, query_poll))) {
            uv_close((uv_handle_t *)qi->handle, NULL);
            goto uv_error;
        }
        else
            return;
    }

ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto error;
ldns_qerror:
    assert(qi->error);
    errstr_cstr = ldns_lookup_by_id(ldns_rcodes, (int)qi->error)->name;
    goto error;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
    goto error;
error:
    assert(errstr_cstr);
    MVMROOT(tc, task, {
        MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVM_repr_push_o(tc, result, task->body.schedulee);
        MVMROOT(tc, result, {
            /* Push the error message: */
            MVMString *errstr = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, errstr_cstr);
            MVM_repr_push_o(tc, result, MVM_repr_box_str(tc, tc->instance->boot_types.BOOTStr, errstr));
        });
        MVM_repr_push_o(tc, task->body.queue, result);
    });

    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
}

static void query_poll(uv_poll_t *handle, int status, int events) {
    QueryInfo *qi = (QueryInfo *)handle->data;
    if (!status) {
        if (events & UV_READABLE) {
            uv_os_fd_t      handle_fh;
            int             handle_fd;
            struct timeval  timeout;
            size_t          wire_size;
            MVMuint8       *wire;

            uv_fileno((uv_handle_t *)handle, &handle_fh);
            handle_fd = uv_open_osfhandle(handle_fh);
            if ((wire = ldns_udp_read_wire(handle_fd, &wire_size, NULL, NULL)))
                query_process(qi, wire, wire_size);
        }
    }
}

static void query_process(QueryInfo *qi, MVMuint8 *wire, size_t wire_size) {
    MVMThreadContext *tc;
    MVMAsyncTask     *task;
    ldns_pkt         *packet;
    ldns_status       status;

    tc   = qi->tc;
    task = (MVMAsyncTask *)MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    if ((status = ldns_wire2pkt(&packet, wire, wire_size))) {
        MVMROOT(tc, task, {
            MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, result, task->body.schedulee);
            MVMROOT(tc, result, {
                /* Push the error message: */
                MVMString *errstr_cstr = MVM_string_ascii_decode_nt(tc,
                    tc->instance->VMString, ldns_get_errorstr_by_id(status));
                MVM_repr_push_o(tc, result, MVM_repr_box_str(tc,
                    tc->instance->boot_types.BOOTStr, errstr_cstr));
            });
            MVM_repr_push_o(tc, task->body.queue, result);
        });
    }
    else if (ldns_pkt_get_rcode(packet) == LDNS_RCODE_NOERROR) {
        MVMROOT(tc, task, {
            MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, result, task->body.schedulee);
            MVMROOT(tc, result, {
                ldns_rr_list *rrs;
                size_t        i;

                /* Push a null error message: */
                MVM_repr_push_o(tc, result, tc->instance->boot_types.BOOTStr);

                /* Push each of the answer section's RRs: */
                rrs = ldns_pkt_answer(packet);
                for (i = 0; i < ldns_rr_list_rr_count(rrs); ++i) {
                    ldns_rr   *rr     = ldns_rr_list_rr(rrs, i);
                    MVMObject *rr_box = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVMROOT(tc, rr_box, {
                        ldns_rr_type   type;
                        ldns_rr_class  class;
                        MVMuint32      ttl;
                        ldns_rdf      *domain_name_ldns;
                        char          *domain_name_cstr;
                        MVMString     *domain_name;

                        /* Push the RR type: */
                        type = ldns_rr_get_type(rr);
                        MVM_repr_push_o(tc, rr_box, MVM_repr_box_int(tc,
                            tc->instance->boot_types.BOOTInt, (MVMint64)type));

                        /* Push the RR class: */
                        class = ldns_rr_get_class(rr);
                        MVM_repr_push_o(tc, rr_box, MVM_repr_box_int(tc,
                            tc->instance->boot_types.BOOTInt, (MVMint64)class));

                        /* Push the RR TTL: */
                        ttl = ldns_rr_ttl(rr);
                        MVM_repr_push_o(tc, rr_box, MVM_repr_box_int(tc,
                            tc->instance->boot_types.BOOTInt, (MVMint64)ttl));

                        /* Push the RR domain name (canonicalized): */
                        domain_name_ldns = ldns_rdf_clone(ldns_rr_owner(rr));
                        ldns_dname2canonical(domain_name_ldns);
                        domain_name_cstr = ldns_rdf2str(domain_name_ldns);
                        domain_name      = MVM_string_ascii_decode(tc,
                            tc->instance->VMString, domain_name_cstr, strlen(domain_name_cstr) - 1);
                        MVM_repr_push_o(tc, rr_box, MVM_repr_box_str(tc,
                            tc->instance->boot_types.BOOTStr, domain_name));
                        MVM_free(domain_name_cstr);
                        ldns_rdf_deep_free(domain_name_ldns);

                        /* Push the RR data: */
                        switch (type) {
                            case LDNS_RR_TYPE_A: {
                                ldns_rdf           *ldns_address;
                                size_t              native_address_len;
                                struct sockaddr_in *native_address;
                                MVMAddress         *address;

                                ldns_address   = ldns_rr_rdf(rr, 0);
                                native_address = (struct sockaddr_in *)ldns_rdf2native_sockaddr_storage(
                                    ldns_address, 0, &native_address_len);
                                address        = (MVMAddress *)MVM_repr_alloc_init(tc,
                                    tc->instance->boot_types.BOOTAddress);
                                memcpy(&address->body.storage.ip4, native_address, sizeof(*native_address));
                                MVM_repr_push_o(tc, rr_box, (MVMObject *)address);
                                break;
                            }
                            default:
                                break; /* TODO */
                        }
                    });

                    MVM_repr_push_o(tc, result, rr_box);
                }
            });
            MVM_repr_push_o(tc, task->body.queue, result);
        });
    }
    else {
        /* We got an error in the response. Query the next name server: */
        qi->error = ldns_pkt_get_rcode(packet);
        return query_init(qi);
    }

    uv_close((uv_handle_t *)qi->handle, NULL);
    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
}

/* TODO: query_cancel */

static void query_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    QueryInfo *qi = (QueryInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &(qi->resolver));
    MVM_gc_worklist_add(tc, worklist, &(qi->domain_name));
}

static void query_gc_free(MVMThreadContext *tc, MVMObject *async_task, void *data) {
    if (data) {
        QueryInfo *qi = (QueryInfo *)data;
        if (qi->question)
            ldns_buffer_free(qi->question);
        if (qi->handle)
            MVM_free(qi->handle);
        MVM_free(qi);
    }
}

static const MVMAsyncTaskOps query_op_table = {
    query_setup,
    NULL, /* query_permit */
    NULL, /* query_cancel */
    query_gc_mark,
    query_gc_free,
};

MVMObject * MVM_io_dns_query_async(MVMThreadContext *tc,
        MVMResolver *resolver, MVMObject *queue, MVMObject *schedulee,
        MVMString *domain_name, MVMint64 type, MVMint64 class,
        MVMObject *async_task) {
    MVMAsyncTask *task;
    QueryInfo    *qi;

    /* Create our async task handle: */
    MVMROOT5(tc, resolver, queue, schedulee, domain_name, async_task, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc, async_task);
    });
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.queue, queue);
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.schedulee, schedulee);
    task->body.ops  = &query_op_table;
    qi              = MVM_calloc(1, sizeof(QueryInfo));
    MVM_ASSIGN_REF(tc, &(task->common.header), qi->resolver, resolver);
    MVM_ASSIGN_REF(tc, &(task->common.header), qi->domain_name, domain_name);
    qi->type        = (ldns_rr_type)type;
    qi->class       = (ldns_rr_class)class;
    task->body.data = qi;

    /* Hand the task off to the event loop: */
    MVMROOT2(tc, domain_name, async_task, {
        MVM_io_eventloop_queue_work(tc, (MVMObject *)task);
    });

    return (MVMObject *)task;
}
#endif
