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

/* Information pertaining to an asynchronou DNS query. */
typedef struct {
    MVMResolver        *resolver;
    char               *question;
    int                 class;
    int                 type;
    MVMResolverContext *context;
} QueryInfo;

static void poll_connection(void *data, ares_socket_t connection, int readable, int writable);
static void process_query(uv_poll_t *handle, int status, int events);
static void get_answer(void *arg, int status, int timeouts, unsigned char *answer, int answer_len);

/* Callback called after making a connection to a DNS server during a DNS
 * query. */
static void poll_connection(void *data, ares_socket_t connection, int readable, int writable) {
    if (!readable && !writable)
        return;
    else {
        MVMResolverContext *context = *(MVMResolverContext **)data;
        if (!context->handle) {
            int error;

            context->connection   = connection;
            context->handle       = MVM_malloc(sizeof(uv_poll_t));
            context->handle->data = context;
            if ((error = uv_poll_init_socket(context->loop, context->handle, connection))) {
                /* TODO: Give a proper error here instead of letting
                 * ARES_ECANCELLED get thrown in get_answer. */
                ares_cancel(context->channel);
                return;
            }
        }
        uv_poll_start(context->handle,
            (readable ? UV_READABLE : 0) | (writable ? UV_WRITABLE : 0),
            process_query);
    }
}

/* Callback that polls a connection to a DNS server during a query. */
static void process_query(uv_poll_t *handle, int status, int events) {
    MVMResolverContext *context = (MVMResolverContext *)handle->data;
    ares_process_fd(context->channel,
        events & UV_READABLE ? context->connection : ARES_SOCKET_BAD,
        events & UV_WRITABLE ? context->connection : ARES_SOCKET_BAD);
}

/* Callback that processes the response to a DNS query. */
static void get_answer(void *data, int status, int timeouts, unsigned char *answer, int answer_len) {
    QueryInfo          *qi       = (QueryInfo *)data;
    MVMResolver        *resolver = qi->resolver;
    MVMResolverContext *context  = qi->context;
    MVMThreadContext   *tc       = context->tc;
    MVMAsyncTask       *task     = MVM_io_eventloop_get_active_work(tc, context->work_idx);
    if (status) {
        MVMROOT(tc, task, {
            MVMObject *arr;
            MVMString *msg_string;

            arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, task->body.schedulee);
            if (status == ARES_ENODATA)
                MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
            else {
                MVMROOT(tc, arr, {
                    msg_string = MVM_string_ascii_decode_nt(tc,
                        tc->instance->VMString, ares_strerror(status));
                    MVMROOT(tc, msg_string, {
                        MVMObject *msg_box = MVM_repr_box_str(tc,
                            tc->instance->boot_types.BOOTStr, msg_string);
                        MVM_repr_push_o(tc, arr, msg_box);
                    });
                });
            }
            switch (qi->type) {
                case MVM_DNS_RECORD_TYPE_A:
                case MVM_DNS_RECORD_TYPE_AAAA:
                    MVMROOT2(tc, arr, msg_string, {
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
                struct hostent *host;
                int             error;
                const char     *errstr;

                errstr = NULL;
                if ((error = ares_parse_a_reply(answer, answer_len, &host, NULL, NULL)))
                    errstr = ares_strerror(error);

                MVMROOT(tc, task, {
                    MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVM_repr_push_o(tc, arr, task->body.schedulee);
                    MVMROOT(tc, arr, {
                        MVMObject *addresses;
                        size_t     i;

                        addresses = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        if (errstr) {
                            MVMROOT(tc, addresses, {
                                MVMString *msg_string = MVM_string_ascii_decode_nt(tc,
                                    tc->instance->VMString, errstr);
                                MVMROOT(tc, msg_string, {
                                    MVMObject *msg_box = MVM_repr_box_str(tc,
                                        tc->instance->boot_types.BOOTStr, msg_string);
                                    MVM_repr_push_o(tc, arr, msg_box);
                                });
                            });
                        }
                        else {
                            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
                            for (i = 0; host->h_addr_list[i]; ++i) {
                                struct in_addr     *native_address = (struct in_addr *)host->h_addr_list[i];
                                struct sockaddr_in  socket_address;
                                memset(&socket_address, 0, sizeof(socket_address));
                                MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, sizeof(socket_address));
                                socket_address.sin_family = AF_INET;
                                memcpy(&socket_address.sin_addr, native_address, sizeof(struct in_addr));
                                MVMROOT(tc, addresses, {
                                    MVMAddress *address = (MVMAddress *)MVM_repr_alloc_init(tc,
                                        tc->instance->boot_types.BOOTAddress);
                                    memcpy(&address->body.storage, &socket_address,
                                        MVM_address_get_storage_length(tc, (struct sockaddr *)&socket_address));
                                    MVM_repr_push_o(tc, addresses, (MVMObject *)address);
                                });
                            }
                            ares_free_hostent(host);
                        }
                        MVM_repr_push_o(tc, arr, addresses);
                    });
                    MVM_repr_push_o(tc, task->body.queue, arr);
                });
                break;
            }
            case MVM_DNS_RECORD_TYPE_AAAA: {
                struct hostent *host;
                int             error;
                const char     *errstr;

                errstr = NULL;
                if ((error = ares_parse_aaaa_reply(answer, answer_len, &host, NULL, NULL)))
                    errstr = ares_strerror(error);

                MVMROOT(tc, task, {
                    MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVM_repr_push_o(tc, arr, task->body.schedulee);
                    MVMROOT(tc, arr, {
                        MVMObject *addresses;
                        size_t     i;

                        addresses = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        if (errstr) {
                            MVMROOT(tc, addresses, {
                                MVMString *msg_string = MVM_string_ascii_decode_nt(tc,
                                    tc->instance->VMString, errstr);
                                MVMROOT(tc, msg_string, {
                                    MVMObject *msg_box = MVM_repr_box_str(tc,
                                        tc->instance->boot_types.BOOTStr, msg_string);
                                    MVM_repr_push_o(tc, arr, msg_box);
                                });
                            });
                            MVM_repr_push_o(tc, arr, addresses);
                        }
                        else {
                            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
                            for (i = 0; host->h_addr_list[i]; ++i) {
                                struct in6_addr     *native_address = (struct in6_addr *)host->h_addr_list[i];
                                struct sockaddr_in6  socket_address;
                                memset(&socket_address, 0, sizeof(socket_address));
                                MVM_address_set_storage_length(tc, (struct sockaddr *)&socket_address, sizeof(socket_address));
                                socket_address.sin6_family = AF_INET6;
                                memcpy(&socket_address.sin6_addr, native_address, sizeof(struct in6_addr));
                                MVMROOT(tc, addresses, {
                                    MVMAddress *address = (MVMAddress *)MVM_repr_alloc_init(tc,
                                        tc->instance->boot_types.BOOTAddress);
                                    memcpy(&address->body.storage, &socket_address,
                                        MVM_address_get_storage_length(tc, (struct sockaddr *)&socket_address));
                                    MVM_repr_push_o(tc, addresses, (MVMObject *)address);
                                });
                            }
                            ares_free_hostent(host);
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
    }

    if (context->handle) {
        uv_poll_stop(context->handle);
        MVM_free_null(context->handle);
    }
    MVM_io_eventloop_remove_active_work(context->tc, &(context->work_idx));
    uv_sem_post(&context->sem_query);
    uv_sem_post(&resolver->body.sem_contexts);
}

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    QueryInfo          *qi;
    MVMResolverContext *context;
    MVMResolver        *resolver;
    size_t              i;
    char               *question;

    /* Grab a DNS resolution context and set it up with our query info: */
    qi       = (QueryInfo *)data;
    resolver = qi->resolver;
    MVM_gc_mark_thread_blocked(tc);
    uv_sem_wait(&resolver->body.sem_contexts);
    MVM_gc_mark_thread_unblocked(tc);
    for (context = resolver->body.contexts; context != resolver->body.contexts + MVM_RESOLVER_POOL_SIZE; ++context) {
        if (!uv_sem_trywait(&context->sem_query)) {
            qi->context = context;
            break;
        }
    }

    /* Prepare the DNS resolution context: */
    if (!context->configured) {
        struct ares_options options;
        int                 mask;
        int                 error;

        memset(&options, 0, sizeof(options));
        options.sock_state_cb      = poll_connection;
        options.sock_state_cb_data = &context;
        mask                       = ARES_OPT_SOCK_STATE_CB;
        if ((error = ares_init_options(&context->channel, &options, mask))) {
            uv_sem_post(&context->sem_query);
            uv_sem_post(&resolver->body.sem_contexts);
            MVM_exception_throw_adhoc(tc,
                "Failed to configure a DNS resolution context: %s",
                ares_strerror(error));
        }
        context->configured = 1;
    }
    context->tc       = tc;
    context->work_idx = MVM_io_eventloop_add_active_work(tc, async_task);
    context->loop     = loop;

    /* Start the DNS query: */
    ares_query(context->channel, qi->question, qi->class, qi->type, get_answer, qi);
    /* poll_connection or get_answer should get called at some point after this. */
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
    NULL, /* cancel */
    query_gc_mark,
    query_gc_free,
};

MVMObject * MVM_io_dns_query_async(MVMThreadContext *tc,
        MVMObject *resolver, MVMString *question, MVMint64 class, MVMint64 type,
        MVMObject *queue, MVMObject *schedulee, MVMObject *async_type) {
    MVMAsyncTask *task;
    QueryInfo    *qi;

    /* Validate REPRs. */
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
