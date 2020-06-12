#include "moar.h"

#ifdef _WIN32
#include <ws2tcpip.h>

#define sa_family_t unsigned int
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
    hints.ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV;
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
        });
    });

    freeaddrinfo(result);
    return arr;
}


static int  on_connect(ares_socket_t connection, int type, void *data);
static void poll_connection(void *data, ares_socket_t connection, int readable, int writable);
static void process_query(uv_poll_t *handle, int status, int events);
static void get_answer(void *arg, int status, int timeouts, unsigned char *answer, int answer_len);
static void finish_query(MVMResolverQueryInfo *handle);

/* Callback called once a connection to a DNS server has been established. */
static int on_connect(ares_socket_t connection, int type, void *data) {
    MVMResolverContext   *context;
    MVMResolverQueryInfo *qi;
    MVMThreadContext     *tc;
    int                   error;

    context          = (MVMResolverContext *)data;
    uv_rwlock_rdlock(context->rwlock_query_info);
    qi               = context->query_info;
    uv_rwlock_rdunlock(context->rwlock_query_info);
    tc               = qi->tc;
    qi->connection   = connection;
    qi->handle       = MVM_malloc(sizeof(uv_poll_t));
    qi->handle->data = qi;
    if ((error = uv_poll_init_socket(qi->loop, qi->handle, connection))) {
        MVMResolver  *resolver = qi->resolver;
        MVMAsyncTask *task     = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
        MVMROOT2(tc, resolver, task, {
            MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, task->body.schedulee);
            MVMROOT(tc, arr, {
                MVMString *msg_string = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, uv_strerror(error));
                MVMROOT(tc, msg_string, {
                    MVMObject *msg_box = MVM_repr_box_str(tc,
                        tc->instance->boot_types.BOOTStr, msg_string);
                    MVM_repr_push_o(tc, arr, msg_box);
                });
            });
            switch (qi->type) {
                case MVM_DNS_RECORD_TYPE_A:
                case MVM_DNS_RECORD_TYPE_AAAA:
                    MVMROOT(tc, arr, {
                        MVMObject *presentations = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        MVM_repr_push_o(tc, arr, presentations);
                    });
                    break;
                default:
                    MVM_exception_throw_adhoc(tc, "Unsupported DNS record type: %d\n", qi->type);
            }
            MVM_repr_push_o(tc, task->body.queue, arr);
        });
        finish_query(qi);
        return -1;
    }
    else
        return ARES_SUCCESS;
}

/* Callback called after making a connection to a DNS server during a DNS
 * query. */
static void poll_connection(void *data, ares_socket_t connection, int readable, int writable) {
    MVMResolverContext   *context;
    MVMResolverQueryInfo *qi;

    context = (MVMResolverContext *)data;
    uv_rwlock_rdlock(context->rwlock_query_info);
    qi      = context->query_info;
    uv_rwlock_rdunlock(context->rwlock_query_info);
    assert(qi != NULL);

    if (readable || writable) {
        uv_poll_start(qi->handle,
            (readable ? UV_READABLE : 0) | (writable ? UV_WRITABLE : 0),
            process_query);
    }
    else
        finish_query(qi);
}

/* Callback that polls a connection to a DNS server, called during a DNS query. */
static void process_query(uv_poll_t *handle, int status, int events) {
    MVMResolverQueryInfo *qi = (MVMResolverQueryInfo *)handle->data;
    ares_process_fd(qi->context->channel,
        events & UV_READABLE ? qi->connection : ARES_SOCKET_BAD,
        events & UV_WRITABLE ? qi->connection : ARES_SOCKET_BAD);
}

/* Callback that processes the response to a DNS query. */
static void get_answer(void *data, int status, int timeouts, unsigned char *answer, int answer_len) {
    MVMResolverQueryInfo *qi       = (MVMResolverQueryInfo *)data;
    MVMThreadContext     *tc       = qi->tc;
    MVMAsyncTask         *task     = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
    MVMResolver          *resolver = qi->resolver;
    if (status) {
        MVMROOT2(tc, resolver, task, {
            MVMObject *arr;
            MVMString *msg_string;

            arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, task->body.schedulee);
            MVMROOT(tc, arr, {
                msg_string = MVM_string_ascii_decode_nt(tc,
                    tc->instance->VMString, ares_strerror(status));
                MVMROOT(tc, msg_string, {
                    MVMObject *msg_box = MVM_repr_box_str(tc,
                        tc->instance->boot_types.BOOTStr, msg_string);
                    MVM_repr_push_o(tc, arr, msg_box);
                });
            });
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

                MVMROOT2(tc, resolver, task, {
                    MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVM_repr_push_o(tc, arr, task->body.schedulee);
                    MVMROOT(tc, arr, {
                        MVMObject  *presentations;
                        size_t      i;

                        presentations = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        if (errstr) {
                            MVMROOT(tc, presentations, {
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
                                struct in_addr *native_address;
                                char            presentation_cstr[INET_ADDRSTRLEN];

                                native_address = (struct in_addr *)host->h_addr_list[i];
                                inet_ntop(AF_INET, native_address, presentation_cstr, sizeof(presentation_cstr));
                                MVMROOT(tc, presentations, {
                                    MVMString *presentation = MVM_string_ascii_decode_nt(tc,
                                        tc->instance->VMString, presentation_cstr);
                                    MVMROOT(tc, presentation, {
                                        MVMObject *presentation_box = MVM_repr_box_str(tc,
                                            tc->instance->boot_types.BOOTStr, presentation);
                                        MVM_repr_push_o(tc, presentations, presentation_box);
                                    });
                                });
                            }
                        }
                        MVM_repr_push_o(tc, arr, presentations);
                        MVM_repr_push_o(tc, task->body.queue, arr);
                    });
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

                MVMROOT2(tc, resolver, task, {
                    MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                    MVM_repr_push_o(tc, arr, task->body.schedulee);
                    MVMROOT(tc, arr, {
                        MVMObject  *presentations;
                        size_t      i;

                        presentations = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
                        if (errstr) {
                            MVMROOT(tc, presentations, {
                                MVMString *msg_string = MVM_string_ascii_decode_nt(tc,
                                    tc->instance->VMString, errstr);
                                MVMROOT(tc, msg_string, {
                                    MVMObject *msg_box = MVM_repr_box_str(tc,
                                        tc->instance->boot_types.BOOTStr, msg_string);
                                    MVM_repr_push_o(tc, arr, msg_box);
                                });
                            });
                            MVM_repr_push_o(tc, arr, presentations);
                        }
                        else {
                            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
                            for (i = 0; host->h_addr_list[i]; ++i) {
                                struct in6_addr *native_address;
                                char             presentation_cstr[INET6_ADDRSTRLEN];

                                native_address = (struct in6_addr *)host->h_addr_list[i];
                                inet_ntop(AF_INET6, native_address, presentation_cstr, sizeof(presentation_cstr));
                                MVMROOT(tc, presentations, {
                                    MVMString *presentation = MVM_string_ascii_decode_nt(tc,
                                        tc->instance->VMString, presentation_cstr);
                                    MVMROOT(tc, presentation, {
                                        MVMObject *presentation_box = MVM_repr_box_str(tc,
                                            tc->instance->boot_types.BOOTStr, presentation);
                                        MVM_repr_push_o(tc, presentations, presentation_box);
                                    });
                                });
                            }
                        }
                        MVM_repr_push_o(tc, arr, presentations);
                        MVM_repr_push_o(tc, task->body.queue, arr);
                    });
                });
                break;
            }
            default:
                MVM_exception_throw_adhoc(tc, "Unsupported DNS query type: %d", qi->type);
        }
    }
}

/* Cleans up after the DNS query once it has been completed. */
static void finish_query(MVMResolverQueryInfo *qi) {
    MVMResolver        *resolver = qi->resolver;
    MVMResolverContext *context  = qi->context;
    uv_poll_stop(qi->handle);
    uv_rwlock_wrlock(context->rwlock_query_info);
    context->query_info = NULL;
    uv_rwlock_wrunlock(context->rwlock_query_info);
    uv_sem_post(resolver->body.sem_contexts);
    MVM_io_eventloop_remove_active_work(qi->tc, &(qi->work_idx));
}

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMResolverQueryInfo *qi;
    MVMResolverContext   *context;
    MVMResolver          *resolver;

    /* Set up the DNS resolver context with our query info: */
    qi       = (MVMResolverQueryInfo *)data;
    context  = NULL;
    resolver = qi->resolver;
    uv_sem_wait(resolver->body.sem_contexts);
    for (context = resolver->body.contexts; context != resolver->body.contexts + MVM_RESOLVER_CONTEXTS; ++context) {
        uv_rwlock_rdlock(context->rwlock_query_info);
        if (context->query_info == NULL) {
            uv_rwlock_rdunlock(context->rwlock_query_info);
            uv_rwlock_wrlock(context->rwlock_query_info);
            context->query_info = qi;
            uv_rwlock_wrunlock(context->rwlock_query_info);
            break;
        }
        else
            uv_rwlock_rdunlock(context->rwlock_query_info);
    }

    /* Set up c-ares if it hasn't been set up already: */
    if (!ares_library_initialized())
        ares_library_init_mem(ARES_LIB_INIT_ALL, MVM_malloc, MVM_free, MVM_realloc);

    /* Configure the DNS resolution context if it hasn't been configured already: */
    if (!context->configured) {
        struct ares_options options;
        int                 mask;
        int                 error;

        memset(&options, 0, sizeof(options));
        options.timeout            = 1000;
        options.sock_state_cb      = poll_connection;
        options.sock_state_cb_data = context;
        mask                       = ARES_OPT_TIMEOUTMS | ARES_OPT_SOCK_STATE_CB;
        if ((error = ares_init_options(&context->channel, &options, mask)))
            MVM_exception_throw_adhoc(tc,
                "Failed to configure a DNS resolution context: %s",
                ares_strerror(error));
        ares_set_socket_callback(context->channel, on_connect, context);
        context->configured = 1;
    }

    /* Continue setting up our DNS query info: */
    qi->tc       = tc;
    qi->work_idx = MVM_io_eventloop_add_active_work(tc, async_task);
    qi->loop     = loop;
    qi->context  = context;

    /* Begin the query: */
    ares_query(context->channel, qi->question, qi->class, qi->type, get_answer, qi);
    /* on_connect and poll_connection should get called at some point after this,
     * which will complete the query info. */
}

static void query_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    MVMResolverQueryInfo *qi = (MVMResolverQueryInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &(qi->resolver));
}

static void query_gc_free(MVMThreadContext *tc, MVMObject *async_task, void *data) {
    if (data) {
        MVMResolverQueryInfo *qi = (MVMResolverQueryInfo *)data;
        MVM_free(qi->question);
        if (qi->handle)
            MVM_free(qi->handle);
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
        MVMObject *resolver, MVMString *question, MVMint64 type, MVMint64 class,
        MVMObject *queue, MVMObject *schedulee, MVMObject *async_type) {
    MVMAsyncTask         *task;
    MVMResolverQueryInfo *qi;

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

    switch (type) {
        case MVM_DNS_RECORD_TYPE_A:
        case MVM_DNS_RECORD_TYPE_AAAA:
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported DNS record type: %"PRIi64"", type);
            break;
    }

    switch (class) {
        case MVM_DNS_RECORD_CLASS_IN:
            break;
        default:
            MVM_exception_throw_adhoc(tc, "Unsupported DNS record class: %"PRIi64"", class);
    }

    /* Create the async task handle. */
    MVMROOT5(tc, resolver, question, queue, schedulee, async_type, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc, async_type);
        MVM_ASSIGN_REF(tc, &(task->common.header), task->body.queue, queue);
        MVM_ASSIGN_REF(tc, &(task->common.header), task->body.schedulee, schedulee);
        task->body.ops = &query_op_table;

        qi = MVM_calloc(1, sizeof(MVMResolverQueryInfo));
        MVM_ASSIGN_REF(tc, &(task->common.header), qi->resolver, resolver);
        qi->question    = MVM_string_utf8_encode_C_string(tc, question);
        qi->type        = (int)type;
        qi->class       = (int)class;
        task->body.data = qi;

        /* Hand the task off to the event loop. */
        MVMROOT(tc, task, {
            MVM_io_eventloop_queue_work(tc, (MVMObject *)task);
        });
    });

    return (MVMObject *)task;
}
