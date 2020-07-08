#include "moar.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

MVMObject * MVM_io_dns_resolve(MVMThreadContext *tc,
        MVMString *host, MVMuint16 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive) {
    char *host_cstr;
    char  port_cstr[8];

    struct addrinfo hints, *result;
    int             error;

    MVMObject *arr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = MVM_address_to_native_family(tc, family);
    hints.ai_socktype = MVM_address_to_native_type(tc, type);
    hints.ai_protocol = MVM_address_to_native_protocol(tc, protocol);
    hints.ai_flags    = AI_NUMERICSERV;
    if (passive) hints.ai_flags |= AI_PASSIVE;

    host_cstr = MVM_string_utf8_encode_C_string(tc, host);
    snprintf(port_cstr, 8, "%"PRIu16"", port);

    MVM_gc_mark_thread_blocked(tc);
    error = getaddrinfo(host_cstr, port_cstr, &hints, &result);
    MVM_gc_mark_thread_unblocked(tc);
    if (error) {
        char *waste[] = { host_cstr, NULL };
        MVM_exception_throw_adhoc_free(
            tc, waste, "Failed to resolve host name '%s' with family %"PRIi64".\nError: %s",
            host_cstr, family, gai_strerror(error)
        );
    }
    MVM_free(host_cstr);

    MVMROOT(tc, host, {
        arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVMROOT(tc, arr, {
            struct addrinfo *native_address_info;
            for (
                native_address_info = result;
                native_address_info != NULL;
                native_address_info = native_address_info->ai_next
            ) {
                int protocol = native_address_info->ai_protocol;
                if (protocol == 0 || protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_RAW) {
                    MVMObject  *address_info   = NULL;
                    MVMAddress *address        = NULL;
                    MVMObject  *boxed_family   = NULL;
                    MVMObject  *boxed_type     = NULL;
                    MVMObject  *boxed_protocol = NULL;
                    MVMROOT5(tc, address_info, address, boxed_family, boxed_type, boxed_protocol, {
                        address_info = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        address      = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                        memcpy(&address->body.storage, native_address_info->ai_addr, native_address_info->ai_addrlen);

                        boxed_family   = MVM_repr_box_int(tc,
                            tc->instance->boot_types.BOOTInt,
                            MVM_address_from_native_family(tc, native_address_info->ai_family));
                        boxed_type     = MVM_repr_box_int(tc,
                            tc->instance->boot_types.BOOTInt,
                            MVM_address_from_native_type(tc, native_address_info->ai_socktype));
                        boxed_protocol = MVM_repr_box_int(tc,
                            tc->instance->boot_types.BOOTInt,
                            MVM_address_from_native_protocol(tc, native_address_info->ai_protocol));

                        MVM_repr_push_o(tc, address_info, (MVMObject *)address);
                        MVM_repr_push_o(tc, address_info, boxed_family);
                        MVM_repr_push_o(tc, address_info, boxed_type);
                        MVM_repr_push_o(tc, address_info, boxed_protocol);
                        MVM_repr_push_o(tc, arr, address_info);
                    });
                }
            }
        });
    });

    freeaddrinfo(result);
    return arr;
}

/* Information pertaining to an asynchronous DNS query: */
typedef struct {
    MVMResolver *resolver;
    char        *question;
    int          class;
    int          type;

    MVMThreadContext *tc;
    int               work_idx;
    struct dns_query *query;
} QueryInfo;

/* Callbacks pertaining to performing asynchronous DNS queries themselves: */
static void query_poll(struct dns_ctx *ctx, int timeout, void *data);
static void query_process(uv_poll_t *handle, int status, int events);
static void query_finish(struct dns_ctx *ctx, void *result, void *data);

/* Callback set upon DNS resolution context's configuration to handle setting
   any timeouts UDNS requests during a DNS query: */
static void query_poll(struct dns_ctx *ctx, int timeout, void *data) {
    if (!data);
        /* UDNS wants us to clean up the timer and poll handle used if we
           get here, but we reuse those between batches of DNS queries. */
    else {
        uv_poll_t *handle = (uv_poll_t *)data;
        if (timeout >= 0)
            uv_poll_start(handle, UV_READABLE | UV_WRITABLE, query_process);
        else
            uv_poll_stop(handle);
    }
}

/* Callback called after polling the DNS resolution context's socket to
   handle reads and writes: */
static void query_process(uv_poll_t *handle, int status, int events) {
    if (status);
        /* TODO: Error handling of some sort (maybe). */
    else {
        struct dns_ctx *ctx = (struct dns_ctx *)handle->data;
        if (events & UV_WRITABLE)
            (void)dns_timeouts(ctx, -1, 0);
        if (events & UV_READABLE)
            dns_ioevent(ctx, 0);
    }
}

/* Callback called after a DNS query has been completed to allow the RR to be
   returned by the asyncdnsquery op: */
static void query_finish(struct dns_ctx *ctx, void *result, void *data) {
    QueryInfo        *qi;
    MVMThreadContext *tc;
    MVMAsyncTask     *task;

    qi        = (QueryInfo *)data;
    qi->query = NULL; /* ...so we don't attempt to cancel completed queries. */
    tc        = qi->tc;
    task      = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    if (!result) {
        MVMROOT(tc, task, {
            MVMObject  *arr      = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVMString  *msg_str  = NULL;
            const char *msg_cstr = NULL;
            switch (dns_status(ctx)) {
                case DNS_E_NODATA:
                    /* Ignore. We let the runtime know when this happens by
                     * giving it an empty response. */
                    break;
                default:
                    msg_cstr = dns_strerror(dns_status(ctx));
                    break;
            }

            MVM_repr_push_o(tc, arr, task->body.schedulee);
            if (msg_cstr == NULL)
                MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
            else
                MVMROOT(tc, arr, {
                    msg_str = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, msg_cstr);
                    MVMROOT(tc, msg_str, {
                        MVMObject *msg_box = MVM_repr_box_str(tc,
                            tc->instance->boot_types.BOOTStr, msg_str);
                        MVM_repr_push_o(tc, arr, msg_box);
                    });
                });
            switch (qi->type) {
                case MVM_DNS_RECORD_TYPE_A:
                case MVM_DNS_RECORD_TYPE_AAAA:
                    MVMROOT2(tc, arr, msg_str, {
                        MVMObject *presentations = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        MVM_repr_push_o(tc, arr, presentations);
                    });
                    break;
                default:
                    MVM_exception_throw_adhoc(tc, "Unsupported DNS query type: %d", qi->type);
            }
            MVM_repr_push_o(tc, task->body.queue, arr);
        });
    }
    else {
        switch (qi->type) {
            case MVM_DNS_RECORD_TYPE_A: {
                MVMROOT(tc, task, {
                    MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVM_repr_push_o(tc, arr, task->body.schedulee);
                    MVMROOT(tc, arr, {
                        struct dns_rr_a4 *answer;
                        MVMObject        *addresses;
                        size_t            i;

                        answer    = (struct dns_rr_a4 *)result;
                        addresses = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
                        for (i = 0; i < answer->dnsa4_nrr; ++i) {
                            struct in_addr     native_address = answer->dnsa4_addr[i];
                            struct sockaddr_in socket_address;
                            memset(&socket_address, 0, sizeof(socket_address));
                            MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, sizeof(socket_address));
                            socket_address.sin_family = AF_INET;
                            memcpy(&socket_address.sin_addr, &native_address, sizeof(struct in_addr));
                            MVMROOT(tc, addresses, {
                                MVMAddress *address = (MVMAddress *)MVM_repr_alloc_init(tc,
                                    tc->instance->boot_types.BOOTAddress);
                                memcpy(&address->body.storage, &socket_address,
                                    MVM_address_get_storage_length(tc, (struct sockaddr *)&socket_address));
                                MVM_repr_push_o(tc, addresses, (MVMObject *)address);
                            });
                        }
                        MVM_repr_push_o(tc, arr, addresses);
                    });
                    MVM_repr_push_o(tc, task->body.queue, arr);
                });
                break;
            }
            case MVM_DNS_RECORD_TYPE_AAAA: {
                MVMROOT(tc, task, {
                    MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVM_repr_push_o(tc, arr, task->body.schedulee);
                    MVMROOT(tc, arr, {
                        struct dns_rr_a6 *answer;
                        MVMObject        *addresses;
                        size_t            i;

                        answer    = (struct dns_rr_a6 *)result;
                        addresses = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
                        for (i = 0; i < answer->dnsa6_nrr; ++i) {
                            struct in6_addr     native_address = answer->dnsa6_addr[i];
                            struct sockaddr_in6 socket_address;
                            memset(&socket_address, 0, sizeof(socket_address));
                            MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, sizeof(socket_address));
                            socket_address.sin6_family = AF_INET6;
                            memcpy(&socket_address.sin6_addr, &native_address, sizeof(struct in6_addr));
                            MVMROOT(tc, addresses, {
                                MVMAddress *address = (MVMAddress *)MVM_repr_alloc_init(tc,
                                    tc->instance->boot_types.BOOTAddress);
                                memcpy(&address->body.storage, &socket_address,
                                    MVM_address_get_storage_length(tc, (struct sockaddr *)&socket_address));
                                MVM_repr_push_o(tc, addresses, (MVMObject *)address);
                            });
                        }
                        MVM_repr_push_o(tc, arr, addresses);
                    });
                    MVM_repr_push_o(tc, task->body.queue, arr);
                });
                break;
            }
            default:
                MVM_exception_throw_adhoc(tc, "Unsupported DNS query type: %d", qi->type);
        }

        MVM_free(result);
    }

    MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
}

/* Callbacks handling operations that can be performed with asynchronous DNS
   queries on the I/O event loop: */
static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data);
static void query_cancel(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data);
static void query_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist);
static void query_gc_free(MVMThreadContext *tc, MVMObject *async_task, void *data);

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    QueryInfo    *qi;
    MVMResolver  *resolver;
    dns_parse_fn *parser;

    /* Get our DNS resolution context... */
    qi       = (QueryInfo *)data;
    resolver = qi->resolver;
    switch (qi->type) {
        case MVM_DNS_RECORD_TYPE_A:
            parser = dns_parse_a4;
            break;
        case MVM_DNS_RECORD_TYPE_AAAA:
            parser = dns_parse_a6;
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported DNS record type: %d\n", qi->type);
    }

    /* Configure our DNS resolution context if need be: */
    if (!resolver->body.configured) {
        int fd;
        int error;

        fd = dns_open(resolver->body.ctx);
        if ((error = uv_poll_init_socket(loop, resolver->body.handle, fd)))
            /* XXX: Push to the queue, idiot. */
            MVM_exception_throw_adhoc(tc,
                "Failed to set up a DNS resolution context: %s",
                uv_strerror(error));
        else {
            dns_set_tmcbck(resolver->body.ctx, query_poll, resolver->body.handle);
            resolver->body.configured = 1;
        }
    }

    /* Start the DNS query: */
    qi->tc       = tc;
    qi->work_idx = MVM_io_eventloop_add_active_work(tc, async_task);
    qi->query    = dns_submit_p(resolver->body.ctx,
        qi->question, qi->class, qi->type, 0,
        parser, query_finish, qi);
}

static void query_cancel(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    QueryInfo *qi = (QueryInfo *)data;
    if (qi->query) {
        dns_cancel(qi->resolver->body.ctx, qi->query);
        MVM_io_eventloop_remove_active_work(tc, &(qi->work_idx));
    }
}

static void query_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    QueryInfo *qi = (QueryInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &(qi->resolver));
}

static void query_gc_free(MVMThreadContext *tc, MVMObject *async_task, void *data) {
    if (data) {
        QueryInfo *qi = (QueryInfo *)data;
        MVM_free(qi->question);
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

/* Operation for performing asynchronous DNS queries: */
MVMObject * MVM_io_dns_query_async(MVMThreadContext *tc,
        MVMObject *resolver, MVMString *question, MVMint64 class, MVMint64 type,
        MVMObject *queue, MVMObject *schedulee, MVMObject *async_type) {
    MVMAsyncTask *task;
    QueryInfo    *qi;

    /* Validate the REPRs and DNS RR class and type arguments given: */
    if (REPR(resolver)->ID != MVM_REPR_ID_MVMResolver || !IS_CONCRETE(resolver))
        MVM_exception_throw_adhoc(tc,
            "asyncdnsquery resolver must be a concrete object with the Resolver REPR (got %s)",
            MVM_6model_get_stable_debug_name(tc, resolver->st));
    if (REPR(queue)->ID != MVM_REPR_ID_ConcBlockingQueue || !IS_CONCRETE(resolver))
        MVM_exception_throw_adhoc(tc,
            "asyncdnsquery target queue must be a concrete object with the ConcBlockingQueue REPR (got %s)",
            MVM_6model_get_stable_debug_name(tc, queue->st));
    if (REPR(async_type)->ID != MVM_REPR_ID_MVMAsyncTask)
        MVM_exception_throw_adhoc(tc,
            "asyncdnsquery async task type must have the AsyncTask REPR (got %s)",
            MVM_6model_get_stable_debug_name(tc, async_type->st));

    switch (class) {
        case MVM_DNS_RECORD_CLASS_IN:
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported DNS record class: %"PRIi64"", class);
    }

    switch (type) {
        case MVM_DNS_RECORD_TYPE_A:
        case MVM_DNS_RECORD_TYPE_AAAA:
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported DNS record type: %"PRIi64"", type);
            break;
    }

    /* Create the async task handle: */
    MVMROOT5(tc, resolver, question, queue, schedulee, async_type, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc, async_type);
    });
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.queue, queue);
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.schedulee, schedulee);
    task->body.ops = &query_op_table;

    /* Set up our query info: */
    qi = MVM_calloc(1, sizeof(QueryInfo));
    MVM_ASSIGN_REF(tc, &(task->common.header), qi->resolver, resolver);
    qi->question    = MVM_string_utf8_encode_C_string(tc, question);
    qi->class       = (int)class;
    qi->type        = (int)type;
    task->body.data = qi;

    /* Hand the task off to the event loop: */
    MVMROOT3(tc, question, async_type, task, {
        MVM_io_eventloop_queue_work(tc, (MVMObject *)task);
    });

    return (MVMObject *)task;
}
