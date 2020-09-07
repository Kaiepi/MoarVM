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

#ifdef HAVE_WINDNS
/* TODO */
#else /* HAVE_WINDNS */
/* LDNS does not provide an asynchronous API for handling DNS queries. This
 * library can be made to work in combination with the I/O event loop through
 * its ldns_udp_bgsend and ldns_tcp_bgsend functions, but because these are too
 * low level to handle anything related to DNS resolution contexts, making a
 * query is rather complex from our perspective. The logic we use to perform a
 * DNS query asynchronously is based loosely off how LDNS would handle things
 * under normal circumstances.
 *
 * When we want to make a query, after setup, we iterate through the DNS
 * resolution context's name servers. For each one, we send, poll, and process
 * responses until we either get a valid response or run out of name servers to
 * try. Should an error occur during this process, we retry making the query.
 * How exactly this is done depends on the way the query failed:
 * - In the case of a networking error, we retry up to a configurable number of
 *   times.
 * - In the case of a protocol-level error, we retry with the next name
 *   server.
 *
 * Additionally, we try a few different methods of making a DNS query. The
 * first method we use is straight UDP, which unfortunately comes with a rather
 * stringent maximum packet size by default, but is the most efficient method.
 * If the response happens to be truncated, we fallback to UDP again, this time
 * around using EDNS to allow a larger packet size to be used. If the response
 * still manages to get truncated, then we fallback to TCP, which doesn't have
 * any limitation on packet size, but is the most expensive method to use. */

/* Methods of making a DNS query: */
typedef enum {
    QUERY_METHOD_UDP,
    QUERY_METHOD_EDNS,
    QUERY_METHOD_TCP
} QueryMethod;

/* Information pertaining to asynchronous DNS queries: */
typedef struct {
    /* Information needed to set up the query: */
    MVMResolver   *resolver;
    MVMString     *domain_name;
    ldns_rr_type   type;
    ldns_rr_class  class;

    /* Information needed to interact with the rest of MoarVM: */
    MVMThreadContext *tc;
    uv_loop_t        *loop;
    int               work_idx;

    /* Information pertaining to a query itself: */
    uv_handle_t *query;
    ldns_pkt    *question;
    ldns_pkt    *response;
    size_t       name_server_idx;
    MVMuint8     retry_count;
    QueryMethod  method;
} QueryInfo;

/* Sends a query to a name server. The sending functions used yield a file
 * descriptor, which may be polled for a response. */
static void query_init(uv_prepare_t *setup);

/* Reads from the query's socket and sets up response processing (if we got one). */
static void query_poll(uv_poll_t *handle, int poll_status, int events);

/* Processes the response to a query. */
static void query_process(uv_check_t *teardown);
/* Pushes an integer to an array. */
MVM_STATIC_INLINE void query_push_int(MVMThreadContext *tc, MVMObject *arr, MVMint64 x);
/* Pushes a domain name to an array. */
MVM_STATIC_INLINE void query_push_domain_name(MVMThreadContext *tc, MVMObject *arr, ldns_rdf *rdata);
/* Pushes an address to an array. */
MVM_STATIC_INLINE void query_push_address(MVMThreadContext *tc, MVMObject *arr, ldns_rdf *rdata);

/* Performs any cleanup necessary when completing a query. */
MVM_STATIC_INLINE void query_complete(QueryInfo *qi);
/* Emits an error that we cannot recover from, completing the query: */
MVM_STATIC_INLINE void query_die(QueryInfo *qi, const char *errstr_cstr);

/* Frees a handle associated with the query once it has been closed. */
static void query_free_handle(uv_handle_t *handle);

/* Any other callbacks from hereon out not already declared here are required
 * for async I/O in MoarVM (in our case). */

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMAsyncTask *task;
    QueryInfo    *qi;
    char         *domain_name_cstr;
    ldns_rdf     *domain_name_ldns;
    uv_prepare_t *setup;
    uv_poll_t    *handle;
    uv_check_t   *teardown;
    ldns_status   status;
    int           error;
    const char   *errstr_cstr;

    /* Add to work in progress: */
    task         = (MVMAsyncTask *)async_task;
    qi           = (QueryInfo *)data;
    qi->tc       = tc;
    qi->loop     = loop;
    qi->work_idx = MVM_io_eventloop_add_active_work(tc, async_task);
    status       = LDNS_STATUS_OK;
    error        = 0;
    errstr_cstr  = NULL;

    /* Prepare a DNS packet to send: */
    domain_name_cstr = MVM_string_ascii_encode(tc, qi->domain_name, NULL, 0);
    if ((status = ldns_str2rdf_dname(&domain_name_ldns, domain_name_cstr)))
        goto ldns_error;
    else if ((status = ldns_resolver_prepare_query_pkt(&qi->question, qi->resolver->body.context,
                 domain_name_ldns, qi->type, qi->class, LDNS_RD)))
        goto ldns_error;
    else {
        teardown       = MVM_malloc(sizeof(uv_check_t));
        teardown->data = qi;
        handle         = MVM_malloc(sizeof(uv_poll_t));
        handle->data   = teardown;
        setup          = MVM_malloc(sizeof(uv_prepare_t));
        setup->data    = handle;
        qi->query      = (uv_handle_t *)setup;
        if ((error = uv_check_init(loop, teardown)))
            goto uv_error;
        else if ((error = uv_prepare_init(loop, setup)))
            goto uv_error;
        else if ((error = uv_prepare_start(setup, query_init)))
            goto uv_error;
        else
            goto cleanup;
    }

ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto die;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
die:
    assert(errstr_cstr);
    query_die(qi, errstr_cstr);
cleanup:
    if (domain_name_ldns)
        ldns_rdf_deep_free(domain_name_ldns);
    if (domain_name_cstr)
        MVM_free(domain_name_cstr);
}

static void query_init(uv_prepare_t *setup) {
    uv_poll_t        *handle;
    uv_check_t       *teardown;
    QueryInfo        *qi;
    MVMThreadContext *tc;
    MVMAsyncTask     *task;

    size_t       name_server_count;
    MVMuint8     retry_count;
    size_t       question_size;
    ldns_buffer *question_buffer;

    ldns_status  status;
    int          error;
    const char  *errstr_cstr;

    handle            = (uv_poll_t *)setup->data;
    teardown          = (uv_check_t *)handle->data;
    qi                = (QueryInfo *)teardown->data;
    tc                = qi->tc;
    task              = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    name_server_count = ldns_resolver_nameserver_count(qi->resolver->body.context);
    question_buffer   = NULL;
    error             = 0;
    status            = LDNS_STATUS_OK;
    errstr_cstr       = NULL;
    uv_prepare_stop(setup);

    /* Determine how large a packet we need to make the query: */
    switch (qi->method) {
        case QUERY_METHOD_UDP:
            question_size = LDNS_MIN_BUFLEN;
            break;
        case QUERY_METHOD_EDNS:
            ldns_pkt_set_edns_do(qi->question, 1);
            question_size = ldns_pkt_edns_udp_size(qi->question);
            if (!question_size) {
                question_size = ldns_resolver_edns_udp_size(qi->resolver->body.context);
                ldns_pkt_set_edns_udp_size(qi->question, question_size);
            }
            break;
        case QUERY_METHOD_TCP:
            ldns_pkt_set_edns_do(qi->question, 0);
            question_size = LDNS_MAX_PACKETLEN;
            break;
    }

    /* If we have a name server to make our query to, then prepare our packet
     * to send: */
    if (!name_server_count) {
        status = LDNS_STATUS_RES_NO_NS;
        goto ldns_error;
    }
    else if (qi->name_server_idx == name_server_count) {
        /* Give the final response's RCODE as an error message: */
        ldns_pkt_rcode rcode = ldns_pkt_get_rcode(qi->response);
        errstr_cstr          = ldns_lookup_by_id(ldns_rcodes, (int)rcode)->name;
        goto die;
    }
    else if (!(question_buffer = ldns_buffer_new(question_size))) {
        status = LDNS_STATUS_MEM_ERR;
        goto ldns_error;
    }
    else if ((status = ldns_pkt2buffer_wire(question_buffer, qi->question)))
        goto ldns_error;
    else {
        ldns_rdf                *ldns_address;
        size_t                   native_address_len;
        struct sockaddr_storage *native_address;
        struct timeval           timeout;
        int                      fd;

        /* Prepare the selected name server for our query: */
        ldns_address   = ldns_resolver_nameservers(qi->resolver->body.context)[qi->name_server_idx];
        native_address = ldns_rdf2native_sockaddr_storage(ldns_address, 0, &native_address_len);
        memset(&timeout, 0, sizeof(timeout));

        /* Send our question and start polling (if we succeed): */
        fd = qi->method == QUERY_METHOD_TCP ?
             ldns_tcp_bgsend(question_buffer, native_address, native_address_len, timeout) :
             ldns_udp_bgsend(question_buffer, native_address, native_address_len, timeout);
        if (fd < 0) {
            status = LDNS_STATUS_SOCKET_ERROR;
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

ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto die;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
die:
    assert(errstr_cstr);
    query_die(qi, errstr_cstr);
    query_complete(qi);
cleanup:
    ldns_buffer_free(question_buffer);
}

static void query_poll(uv_poll_t *handle, int poll_status, int events) {
    uv_check_t   *teardown;
    QueryInfo    *qi;
    uv_prepare_t *setup;
    uv_os_fd_t    handle_fh;
    int           handle_fd;
    MVMuint8     *response_wire;
    size_t        response_size;
    ldns_status   response_status;
    int           error;
    const char   *errstr_cstr;

    teardown        = (uv_check_t *)handle->data;
    qi              = (QueryInfo *)teardown->data;
    setup           = (uv_prepare_t *)qi->query;
    uv_fileno((uv_handle_t *)handle, &handle_fh);
    handle_fd       = uv_open_osfhandle(handle_fh);
    response_status = LDNS_STATUS_OK;
    error           = 0;
    errstr_cstr     = NULL;
    uv_close((uv_handle_t *)handle, NULL);

    if (!poll_status && (events & UV_READABLE)) {
        /* Read the response to our query: */
        if ((response_wire = ldns_udp_read_wire(handle_fd, &response_size, NULL, NULL))) {
            /* Prepare to process the response: */
            if (qi->response)
                ldns_pkt_free(qi->response);

            if ((response_status = ldns_wire2pkt(&qi->response, response_wire, response_size)))
                goto ldns_error;
            else if ((error = uv_check_start(teardown, query_process)))
                goto uv_error;
            else
                goto cleanup;
        }
        else {
            /* A networking error of some sort occurred. */
            if (qi->retry_count < ldns_resolver_retry(qi->resolver->body.context))
                /* Retry making the query to the same name server: */
                qi->retry_count++;
            else {
                /* We ran out of attempts for this name server. Retry making
                 * the query with the next one: */
                qi->name_server_idx++;
                qi->retry_count = 0;
                qi->method      = QUERY_METHOD_UDP;
            }

            if ((error = uv_prepare_start(setup, query_init)))
                goto uv_error;
            else
                goto cleanup;
        }
    }
    else if (poll_status == UV_ECANCELED)
        goto cleanup;
    else
        goto uv_error;

ldns_error:
    assert(response_status);
    errstr_cstr = ldns_get_errorstr_by_id(response_status);
    goto die;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
die:
    assert(errstr_cstr);
    query_die(qi, errstr_cstr);
cleanup:
    if (response_wire)
        MVM_free(response_wire);
}

static void query_process(uv_check_t *teardown) {
    QueryInfo        *qi;
    uv_prepare_t     *setup;
    MVMThreadContext *tc;
    MVMAsyncTask     *task;
    ldns_pkt_rcode    rcode;
    ldns_status       status;
    int               error;
    const char       *errstr_cstr;

    qi          = (QueryInfo *)teardown->data;
    setup       = (uv_prepare_t *)qi->query;
    tc          = qi->tc;
    task        = (MVMAsyncTask *)MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    rcode       = ldns_pkt_get_rcode(qi->response);
    status      = LDNS_STATUS_OK;
    error       = 0;
    errstr_cstr = NULL;
    uv_check_stop(teardown);

    if (ldns_pkt_tc(qi->response)) {
        /* We got a truncated response. Retry making the query: */
        qi->retry_count = 0;
        if (ldns_resolver_fallback(qi->resolver->body.context)) {
            /* Fallback to another method of query: */
            switch (qi->method) {
                case QUERY_METHOD_UDP:
                    qi->method = QUERY_METHOD_EDNS;
                    break;
                case QUERY_METHOD_EDNS:
                    qi->method = QUERY_METHOD_TCP;
                    break;
                case QUERY_METHOD_TCP:
                    /* Truncation should never occur with a trustworthy name
                     * server over TCP. Ignore whatever nonsense we got and
                     * use the next name server: */
                    qi->name_server_idx++;
                    qi->method = QUERY_METHOD_UDP;
                    break;
            }
        }
        else {
            /* Use the next name server: */
            qi->name_server_idx++;
            qi->method = QUERY_METHOD_UDP;
        }

        /* Fall through. */
    }
    else if (rcode == LDNS_RCODE_NOERROR) {
        /* We got a successful response! */
        MVMROOT(tc, task, {
            MVMObject *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, result, task->body.schedulee);

            /* Push a null error message: */
            MVM_repr_push_o(tc, result, tc->instance->boot_types.BOOTStr);

            MVMROOT(tc, result, {
                ldns_rr_list *rrs;
                size_t        i;

                /* Push each of the answer section's RRs: */
                rrs = ldns_pkt_answer(qi->response);
                for (i = 0; i < ldns_rr_list_rr_count(rrs); ++i) {
                    ldns_rr   *rr;
                    MVMObject *rr_box;

                    /* Canonicalize any domain names contained by the RR: */
                    rr = ldns_rr_list_rr(rrs, i);
                    ldns_rr2canonical(rr);

                    rr_box = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVMROOT(tc, rr_box, {
                        ldns_rr_type type = ldns_rr_get_type(rr);
                        /* Push the RR type: */
                        query_push_int(tc, rr_box, (MVMint64)type);
                        /* Push the RR class: */
                        query_push_int(tc, rr_box, (MVMint64)ldns_rr_get_class(rr));
                        /* Push the RR TTL: */
                        query_push_int(tc, rr_box, (MVMint64)ldns_rr_ttl(rr));
                        /* Push the RR domain name: */
                        query_push_domain_name(tc, rr_box, ldns_rr_owner(rr));
                        /* Push the RR data: */
                        switch (type) {
                            case LDNS_RR_TYPE_A:
                                query_push_address(tc, rr_box, ldns_rr_rdf(rr, 0));
                                break;
                            default: { /* Fallback (refer to RFC 3597) */
                                size_t    buffer_size;
                                MVMuint8 *buffer_wire;
                                MVMArray *buffer;
                                size_t    j;

                                buffer_size = 0;
                                for (j = 0; j < ldns_rr_rd_count(rr); ++j) {
                                    ldns_rdf *rdata = ldns_rr_rdf(rr, j);
                                    buffer_size += ldns_rdf_size(rdata);
                                }

                                /* XXX TODO: We need to support all well-known
                                 * types of RRs whose data contains domain
                                 * names in order to comply with RFC 3597, as
                                 * these cannot remain compressed like they do
                                 * here! */
                                buffer_wire = MVM_malloc(buffer_size);
                                for (j = 0; j < ldns_rr_rd_count(rr); ++j) {
                                    ldns_rdf *rdata = ldns_rr_rdf(rr, j);
                                    memcpy(buffer_wire, ldns_rdf_data(rdata), ldns_rdf_size(rdata));
                                }

                                buffer                = (MVMArray *)MVM_repr_alloc_init(tc,
                                    qi->resolver->body.buf_type);
                                buffer->body.slots.u8 = buffer_wire;
                                buffer->body.elems    = buffer->body.ssize = buffer_size;
                                MVM_repr_push_o(tc, rr_box, (MVMObject *)buffer);
                                break;
                            }
                        }
                    });

                    MVM_repr_push_o(tc, result, rr_box);
                }
            });

            MVM_repr_push_o(tc, task->body.queue, result);
        });

        query_complete(qi);
        return;
    }
    else {
        /* We got a protocol-level error. Retry making the query with the next
         * name server: */
        qi->name_server_idx++;
        qi->retry_count = 0;
        qi->method      = QUERY_METHOD_UDP;

        /* Fall through. */
    }

    /* If we get here, then prepare to retry making the query: */
    if ((error = uv_prepare_start(setup, query_init)))
        goto uv_error;
    else
        return;

ldns_error:
    assert(status);
    errstr_cstr = ldns_get_errorstr_by_id(status);
    goto die;
uv_error:
    assert(error);
    errstr_cstr = uv_strerror(error);
die:
    assert(errstr_cstr);
    query_die(qi, errstr_cstr);
}

MVM_STATIC_INLINE void query_push_int(MVMThreadContext *tc, MVMObject *arr, MVMint64 x) {
    MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc,
        tc->instance->boot_types.BOOTInt, (MVMint64)x));
}

MVM_STATIC_INLINE void query_push_domain_name(MVMThreadContext *tc, MVMObject *arr, ldns_rdf *rdata) {
    ldns_rdf_type  rdata_type;
    char          *domain_name_cstr;
    MVMString     *domain_name;

    rdata_type = ldns_rdf_get_type(rdata);
    assert(rdata_type == LDNS_RDF_TYPE_DNAME);

    domain_name_cstr = ldns_rdf2str(rdata);
    domain_name      = MVM_string_ascii_decode(tc, tc->instance->VMString, domain_name_cstr,
        strnlen(domain_name_cstr, LDNS_MAX_DOMAINLEN) - 1); /* Chops the FQDN's root domain. */
    MVM_repr_push_o(tc, arr, MVM_repr_box_str(tc,
        tc->instance->boot_types.BOOTStr, domain_name));
    MVM_free(domain_name_cstr);
}

MVM_STATIC_INLINE void query_push_address(MVMThreadContext *tc, MVMObject *arr, ldns_rdf *rdata) {
    ldns_rdf_type            rdata_type;
    size_t                   native_address_len;
    struct sockaddr_storage *native_address;
    MVMAddress              *address;

    rdata_type = ldns_rdf_get_type(rdata);
    assert(rdata_type == LDNS_RDF_TYPE_A || rdata_type == LDNS_RDF_TYPE_AAAA);

    native_address = (struct sockaddr_storage *)ldns_rdf2native_sockaddr_storage(rdata, 0, &native_address_len);
    address        = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
    memcpy(&address->body.storage.ip4, native_address, native_address_len);
    MVM_repr_push_o(tc, arr, (MVMObject *)address);
    MVM_free(native_address);
}

MVM_STATIC_INLINE void query_complete(QueryInfo *qi) {
    if (qi->query) {
        uv_handle_t *setup    = qi->query;
        uv_handle_t *handle   = (uv_handle_t *)setup->data;
        uv_handle_t *teardown = (uv_handle_t *)handle->data;
        if (!uv_is_closing(setup))
            uv_close(setup, query_free_handle);
        if (!uv_is_closing(handle))
            uv_close(handle, query_free_handle);
        if (!uv_is_closing(teardown))
            uv_close(teardown, query_free_handle);
    }

    MVM_io_eventloop_remove_active_work(qi->tc, &(qi->work_idx));
}

MVM_STATIC_INLINE void query_die(QueryInfo *qi, const char *errstr_cstr) {
    MVMThreadContext *tc     = qi->tc;
    MVMAsyncTask     *task   = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    MVMObject        *result = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
    MVM_repr_push_o(tc, result, task->body.schedulee);
    MVMROOT(tc, task, {
        /* Push the error message: */
        MVMString *errstr = MVM_string_ascii_decode_nt(tc,
            tc->instance->VMString, errstr_cstr);
        MVM_repr_push_o(tc, result, MVM_repr_box_str(tc,
            tc->instance->boot_types.BOOTStr, errstr));
    });
    MVM_repr_push_o(tc, task->body.queue, result);

    query_complete(qi);
}

static void query_free_handle(uv_handle_t *handle) {
    MVM_free(handle);
}

static void query_cancel(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    if (data) {
        QueryInfo *qi = (QueryInfo *)data;
        query_complete(qi);
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
        /* Handles already get freed when they get closed. */
        if (qi->question)
            ldns_pkt_free(qi->question);
        if (qi->response)
            ldns_pkt_free(qi->response);
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

    /* Ensure our resolver is set up for queries: */
    if (!MVM_load(&resolver->body.configured))
        MVM_exception_throw_adhoc(tc,
            "DNS resolvers must be configured before queries can be made with them");

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
#endif /* HAVE_WINDNS */
