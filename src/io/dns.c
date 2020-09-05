#include "moar.h"

#ifdef _MSC_VER
#include <ws2tcpip.h>

#define snprintf _snprintf
#else
#include <sys/socket.h>
#endif

#ifdef HAVE_WINDNS
/* TODO */
#else
#include "unistd.h"
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
        ldns_rdf **ldns_name_servers = MVM_malloc(name_servers->body.elems * sizeof(ldns_rdf *));
        size_t    *ldns_rtt          = MVM_malloc(name_servers->body.elems * sizeof(size_t));
        for (i = 0; i < name_servers->body.elems; ++i) {
            MVMAddress      *address;
            socklen_t        native_address_len;
            struct sockaddr *native_address;
            ldns_rdf        *ldns_address;

            address            = (MVMAddress *)name_servers->body.slots.o[i];
            native_address     = &address->body.storage.any;
            native_address_len = MVM_address_get_storage_length(tc, native_address);
            switch (native_address->sa_family) {
                case AF_INET:
                    ldns_address = ldns_rdf_new_frm_data(
                        LDNS_RDF_TYPE_A,
                        native_address_len,
                        &address->body.storage.ip4.sin_addr);
                    break;
                case AF_INET6:
                    ldns_address = ldns_rdf_new_frm_data(
                        LDNS_RDF_TYPE_AAAA,
                        native_address_len,
                        &address->body.storage.ip6.sin6_addr);
                    break;
                default:
                    error = LDNS_STATUS_UNKNOWN_INET;
                    goto error;
            }

            if (ldns_address) {
                ldns_name_servers[i] = ldns_address;
                ldns_rtt[i]          = LDNS_RESOLV_RTT_MIN;
            }
            else {
                error = LDNS_STATUS_MEM_ERR;
                goto error;
            }
        }
        ldns_resolver_set_nameservers(resolver->body.context, ldns_name_servers);
        ldns_resolver_set_nameserver_count(resolver->body.context, i);
        ldns_resolver_set_rtt(resolver->body.context, ldns_rtt);
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
/* Information pertaining to DNS queries: */
typedef struct {
    MVMResolver   *resolver;
    MVMString     *domain_name;
    ldns_rr_type   type;
    ldns_rr_class  class;

    MVMThreadContext *tc;
    uv_loop_t        *loop;
    int               work_idx;

    MVMuint8        retry_count;
    size_t          name_server_idx;
    ldns_buffer    *question;
    uv_prepare_t   *query;
    MVMuint8       *response;
    size_t          response_size;
    ldns_pkt_rcode  rcode;
} QueryInfo;

/* LDNS does not provide an asynchronous API for handling DNS queries. This
 * library can be made to work in combination with the I/O event loop through
 * its ldns_udp_bgsend and ldns_tcp_bgsend functions, but because these
 * functions are too low level to handle anything related to DNS resolution
 * contexts, making a query is rather complex. To accomplish this, after setup,
 * we iterate through the DNS resolution context's name servers (handling
 * retries as well as we go), sending, polling, and processing responses to
 * queries until we either get a valid response or run out of name servers. */

/* Sends a query to a name server. The sending functions used yield a file
 * descriptor, which may be polled for a response. */
static void query_init(uv_prepare_t *preparation);
/* Reads from the query's socket and sets up response processing (if we get one). */
static void query_poll(uv_poll_t *handle, int status, int events);
/* Processes the response to a query. If the response has an error RCODE, then
 * we loop back to query_init to see if more attempts to make the DNS query
 * should be made. */
static void query_process(uv_check_t *check);

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMAsyncTask *task;
    QueryInfo    *qi;
    char         *domain_name_cstr;
    ldns_rdf     *domain_name;
    ldns_pkt     *packet;
    ldns_status   status;
    int           error;
    const char   *errstr_cstr;

    /* Add to work in progress: */
    task         = (MVMAsyncTask *)async_task;
    qi           = (QueryInfo *)data;
    qi->tc       = tc;
    qi->loop     = loop;
    qi->work_idx = MVM_io_eventloop_add_active_work(tc, async_task);

    status      = LDNS_STATUS_OK;
    error       = 0;
    errstr_cstr = NULL;

    /* Prepare a DNS packet to send: */
    domain_name_cstr = MVM_string_ascii_encode(tc, qi->domain_name, NULL, 0);
    if ((status = ldns_str2rdf_dname(&domain_name, domain_name_cstr)))
        goto ldns_error;
    else if ((status = ldns_resolver_prepare_query_pkt(&packet, qi->resolver->body.context,
                 domain_name, qi->type, qi->class, LDNS_RD)))
        goto ldns_error;
    else if (!(qi->question = ldns_buffer_new(LDNS_MIN_BUFLEN))) {
        status = LDNS_STATUS_MEM_ERR;
        goto ldns_error;
    }
    else if ((status = ldns_pkt2buffer_wire(qi->question, packet)))
        goto ldns_error;
    else {
        uv_check_t *check;
        uv_poll_t  *handle;

        check           = MVM_malloc(sizeof(uv_check_t));
        check->data     = qi;
        handle          = MVM_malloc(sizeof(uv_poll_t));
        handle->data    = check;
        qi->query       = MVM_malloc(sizeof(uv_prepare_t));
        qi->query->data = handle;
        if ((error = uv_check_init(loop, check)))
            goto uv_error;
        else if ((error = uv_prepare_init(loop, qi->query)))
            goto uv_error;
        else if ((error = uv_prepare_start(qi->query, query_init)))
            goto uv_error;
        else
            goto cleanup;
    }

ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto error;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
error:
    MVMROOT(tc, task, {
        MVMObject *result;
        MVMString *errstr;

        result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVM_repr_push_o(tc, result, task->body.schedulee);

        /* Push the error message: */
        errstr = MVM_string_ascii_decode_nt(tc,
            tc->instance->VMString, errstr_cstr);
        MVM_repr_push_o(tc, result, MVM_repr_box_str(tc,
            tc->instance->boot_types.BOOTStr, errstr));

        MVM_repr_push_o(tc, task->body.queue, result);
    });

    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
cleanup:
    if (domain_name)
        ldns_rdf_deep_free(domain_name);
    if (domain_name_cstr)
        MVM_free(domain_name_cstr);
}

static void query_init(uv_prepare_t *preparation) {
    uv_poll_t        *handle;
    uv_check_t       *check;
    QueryInfo        *qi;
    MVMThreadContext *tc;
    MVMAsyncTask     *task;
    MVMuint8          retry_count;
    size_t            name_server_idx;
    ldns_status       status;
    int               error;
    const char       *errstr_cstr;

    handle      = (uv_poll_t *)preparation->data;
    check       = (uv_check_t *)handle->data;
    qi          = (QueryInfo *)check->data;
    tc          = qi->tc;
    task        = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    error       = 0;
    status      = LDNS_STATUS_OK;
    errstr_cstr = NULL;
    uv_prepare_stop(preparation);

    /* Select the next name server to make a DNS query with: */
    retry_count = qi->retry_count++;
    if (retry_count == ldns_resolver_retry(qi->resolver->body.context))
        name_server_idx = ++qi->name_server_idx;
    else
        name_server_idx = qi->name_server_idx;

    if (name_server_idx == ldns_resolver_nameserver_count(qi->resolver->body.context))
        goto ldns_qerror;
    else {
        ldns_rdf                *ldns_address;
        size_t                   native_address_len;
        struct sockaddr_storage *native_address;
        struct timeval           timeout;
        int                      fd;

        /* Prepare the selected name server for a DNS query: */
        ldns_address   = ldns_resolver_nameservers(qi->resolver->body.context)[name_server_idx];
        native_address = ldns_rdf2native_sockaddr_storage(ldns_address, 0, &native_address_len);
        memset(&timeout, 0, sizeof(timeout));

        /* Begin the DNS query: */
        fd = ldns_udp_bgsend(qi->question, native_address, native_address_len, timeout);
        if (fd < 0) {
            status = LDNS_STATUS_NETWORK_ERR;
            goto ldns_error;
        }
        else if ((error = uv_poll_init(qi->loop, handle, fd))) {
            close(fd);
            goto uv_error;
        }
        else if ((error = uv_poll_start(handle, UV_READABLE, query_poll))) {
            close(fd);
            goto uv_error;
        }
        else
            return;
    }

ldns_qerror:
    assert(qi->rcode);
    errstr_cstr = ldns_lookup_by_id(ldns_rcodes, (int)qi->rcode)->name;
    goto error;
ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto error;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
error:
    assert(errstr_cstr);
    MVMROOT(tc, task, {
        MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVM_repr_push_o(tc, result, task->body.schedulee);
        MVMROOT(tc, result, {
            /* Push the error message: */
            MVMString *errstr = MVM_string_ascii_decode_nt(tc,
                tc->instance->VMString, errstr_cstr);
            MVM_repr_push_o(tc, result, MVM_repr_box_str(tc,
                tc->instance->boot_types.BOOTStr, errstr));
        });
        MVM_repr_push_o(tc, task->body.queue, result);
    });

    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
}

static void query_poll(uv_poll_t *handle, int status, int events) {
    uv_check_t *check;
    QueryInfo  *qi;
    uv_os_fd_t  handle_fh;
    int         handle_fd;
    int         error;

    check     = (uv_check_t *)handle->data;
    qi        = (QueryInfo *)check->data;
    uv_fileno((uv_handle_t *)handle, &handle_fh);
    handle_fd = uv_open_osfhandle(handle_fh);
    error     = 0;
    uv_close((uv_handle_t *)handle, NULL);

    if (!status &&
        (events & UV_READABLE) &&
        (qi->response = ldns_udp_read_wire(handle_fd, &qi->response_size, NULL, NULL)) &&
        !(error = uv_check_start(check, query_process)))
        return;
    else if (status == UV_ECANCELED)
        return;
    else {
        MVMThreadContext *tc     = qi->tc;
        MVMAsyncTask     *task   = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
        MVMObject        *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVM_repr_push_o(tc, result, task->body.schedulee);
        MVMROOT(tc, task, {
            /* Push the error message: */
            const char *errstr_cstr = uv_strerror(status);
            MVMString  *errstr      = MVM_string_ascii_decode_nt(tc,
                tc->instance->VMString, errstr_cstr);
            MVM_repr_push_o(tc, result, MVM_repr_box_str(tc,
                tc->instance->boot_types.BOOTStr, errstr));
        });
        MVM_repr_push_o(tc, task->body.queue, result);

        MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
    }
}

static void query_process(uv_check_t *check) {
    QueryInfo        *qi          = (QueryInfo *)check->data;
    MVMThreadContext *tc          = qi->tc;
    MVMAsyncTask     *task        = (MVMAsyncTask *)MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    ldns_pkt         *packet      = NULL;
    ldns_status       status      = LDNS_STATUS_OK;
    int               error       = 0;
    const char       *errstr_cstr = NULL;
    uv_check_stop(check);

    if ((status = ldns_wire2pkt(&packet, qi->response, qi->response_size)))
        goto ldns_error;
    else if (ldns_pkt_get_rcode(packet) == LDNS_RCODE_NOERROR) {
        MVMROOT(tc, task, {
            MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVMROOT(tc, result, {
                ldns_rr_list *rrs;
                size_t        i;

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
                            tc->instance->VMString,
                            domain_name_cstr,
                            strnlen(domain_name_cstr, LDNS_MAX_DOMAINLEN) - 1); /* Chop the FQDN's root domain. */
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
                                memcpy(&address->body.storage.ip4, native_address, native_address_len);
                                MVM_repr_push_o(tc, rr_box, (MVMObject *)address);
                                break;
                            }
                            default: {
                                MVMArray *buffer;
                                size_t    buffer_size;

                                buffer             = (MVMArray *)MVM_repr_alloc_init(tc, qi->resolver->body.buf_type);
                                buffer_size        = 0;
                                status             = ldns_rr2wire(&buffer->body.slots.u8,
                                    rr, LDNS_SECTION_ANSWER, &buffer_size);
                                buffer->body.elems = buffer->body.ssize = buffer_size;
                                MVM_repr_push_o(tc, rr_box, (MVMObject *)buffer);
                                break;
                            }
                        }
                    });

                    MVM_repr_push_o(tc, result, rr_box);
                }
            });

            /* We ignored the schedulee and error string earlier, since errors
             * can occur while boxing RR data. These can be unshifted now: */
            if (!status)
                MVM_repr_unshift_o(tc, result, tc->instance->boot_types.BOOTStr);
            else {
                MVMROOT(tc, result, {
                    MVMString *errstr = MVM_string_ascii_decode_nt(tc,
                        tc->instance->VMString, ldns_get_errorstr_by_id(status));
                    MVM_repr_unshift_o(tc, result, MVM_repr_box_str(tc,
                        tc->instance->boot_types.BOOTStr, errstr));
                });
            }
            MVM_repr_unshift_o(tc, result, task->body.schedulee);

            MVM_repr_push_o(tc, task->body.queue, result);
        });

        goto completion;
    }
    else if ((error = uv_prepare_start(qi->query, query_init)))
        goto uv_error;
    else {
        /* Set up our query state for the next attempt: */
        qi->rcode = ldns_pkt_get_rcode(packet);
        goto cleanup;
    }

ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto error;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
error:
    assert(errstr_cstr);
    MVMROOT(tc, task, {
        MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVM_repr_push_o(tc, result, task->body.schedulee);
        MVMROOT(tc, result, {
            /* Push the error message: */
            MVMString *errstr = MVM_string_ascii_decode_nt(tc,
                tc->instance->VMString, errstr_cstr);
            MVM_repr_push_o(tc, result, MVM_repr_box_str(tc,
                tc->instance->boot_types.BOOTStr, errstr));
        });
        MVM_repr_push_o(tc, task->body.queue, result);
    });
completion:
    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
cleanup:
    if (packet)
        ldns_pkt_free(packet);
}

static void query_cancel(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    if (data) {
        QueryInfo *qi = (QueryInfo *)data;

        if (qi->query) {
            uv_prepare_t *preparation = qi->query;
            uv_poll_t    *handle      = (uv_poll_t *)preparation->data;
            uv_check_t   *check       = (uv_check_t *)handle->data;
            if (uv_is_active((uv_handle_t *)preparation))
                uv_prepare_stop(preparation);
            else if (uv_is_active((uv_handle_t *)handle))
                uv_close((uv_handle_t *)handle, NULL);
            else if (uv_is_active((uv_handle_t *)check))
                uv_check_stop(check);
        }

        MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
    }
}

static void query_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    QueryInfo *qi = (QueryInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &(qi->resolver));
    MVM_gc_worklist_add(tc, worklist, &(qi->domain_name));
}

static void query_gc_free(MVMThreadContext *tc, MVMObject *async_task, void *data) {
    if (data) {
        QueryInfo *qi = (QueryInfo *)data;

        if (qi->query) {
            uv_prepare_t *preparation = qi->query;
            uv_poll_t    *handle      = (uv_poll_t *)preparation->data;
            uv_check_t   *check       = (uv_check_t *)handle->data;
            MVM_free(check);
            MVM_free(handle);
            MVM_free(preparation);
        }

        ldns_buffer_free(qi->question);
        if (qi->response)
            MVM_free(qi->response);

        MVM_free(qi);
    }
}

static const MVMAsyncTaskOps query_op_table = {
    query_setup,
    NULL, /* permit */
    query_cancel,
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
