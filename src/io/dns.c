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


static void poll_connection(void *data, ares_socket_t connection, int readable, int writable);
static void process_query(uv_poll_t *handle, int status, int events);
static void get_answer(void *arg, int status, int timeouts, unsigned char *answer, int answer_len);
static void finish_query(MVMResolverQueryInfo *handle, int remove);

/* Callback called after making a connection to a DNS server during a DNS
 * query. */
static void poll_connection(void *data, ares_socket_t connection, int readable, int writable) {
    MVMResolver          *resolver;
    MVMResolverQueryInfo *qi;
    size_t                i;

    resolver = (MVMResolver *)data;
    qi       = NULL;
    uv_mutex_lock(resolver->body.mutex_pending_queries);
    for (i = 0; i < resolver->body.pending_queries_size; ++i) {
        qi = resolver->body.pending_queries[i];
        if (!qi || !qi->connection || qi->connection == connection)
            break;
    }
    uv_mutex_unlock(resolver->body.mutex_pending_queries);
    if (!qi) return;
    if (!qi->connection) {
        MVMThreadContext *tc;
        int               error;

        tc               = qi->tc;
        qi->handle       = MVM_malloc(sizeof(uv_poll_t));
        qi->handle->data = qi;
        qi->connection   = connection;
        if ((error = uv_poll_init_socket(tc->instance->event_loop, qi->handle, connection))) {
            MVMAsyncTask *task = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
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
            finish_query(qi, 1);
            return;
        }
    }

    if (readable | writable) {
        uv_poll_start(qi->handle,
            (readable ? UV_READABLE : 0) | (writable ? UV_WRITABLE : 0),
            process_query);
    }
}

/* Callback that polls a connection to a DNS server, called during a DNS query. */
static void process_query(uv_poll_t *handle, int status, int events) {
    MVMResolverQueryInfo *qi       = (MVMResolverQueryInfo *)handle->data;
    MVMResolver          *resolver = qi->resolver;
    ares_process_fd(resolver->body.channel,
        events & UV_READABLE ? qi->connection : ARES_SOCKET_BAD,
        events & UV_WRITABLE ? qi->connection : ARES_SOCKET_BAD);
}

/* Callback that processes the response to a DNS query. */
static void get_answer(void *data, int status, int timeouts, unsigned char *answer, int answer_len) {
    MVMResolverQueryInfo *qi       = (MVMResolverQueryInfo *)data;
    MVMResolver          *resolver = qi->resolver;
    if (status)
        return;
    else {
        MVMThreadContext *tc   = qi->tc;
        MVMAsyncTask     *task = MVM_io_eventloop_get_active_work(tc, qi->work_idx);
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
                            MVM_repr_push_o(tc, arr, presentations);
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
                finish_query(qi, 1);
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
                finish_query(qi, 1);
                break;
            }
            default:
                MVM_exception_throw_adhoc(tc, "Unsupported DNS query type: %d", qi->type);
        }
    }
}

/* Cleans up after the DNS query once it has been completed. */
static void finish_query(MVMResolverQueryInfo *qi, int remove) {
    MVMResolver *resolver;
    ssize_t      idx;
    size_t       i;

    resolver = qi->resolver;
    idx      = -1;
    uv_poll_stop(qi->handle);
    uv_mutex_lock(resolver->body.mutex_pending_queries);
    for (i = 0; i < resolver->body.pending_queries_size; ++i) {
        if (resolver->body.pending_queries[i] == qi) {
            idx = i;
            break;
        }
    }
    assert(idx != -1);
    for (i = idx + 1; i < resolver->body.pending_queries_size; ++i) {
        resolver->body.pending_queries[i - 1] = resolver->body.pending_queries[i];
    }
    uv_mutex_unlock(resolver->body.mutex_pending_queries);
    if (remove)
        MVM_io_eventloop_remove_active_work(qi->tc, &(qi->work_idx));
}

static void query_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMResolverQueryInfo *qi;
    MVMResolver          *resolver;
    ssize_t               idx;

    /* Finish setting up our DNS query info: */
    qi           = (MVMResolverQueryInfo *)data;
    qi->tc       = tc;
    qi->work_idx = MVM_io_eventloop_add_active_work(tc, async_task);

    /* Set up the DNS resolver with our query info: */
    resolver = qi->resolver;
    idx      = -1;
    uv_mutex_lock(resolver->body.mutex_pending_queries);
    if (!resolver->body.configured) {
        struct ares_options options;
        int                 mask;
        int                 error;

        memset(&options, 0, sizeof(options));
        options.sock_state_cb      = poll_connection;
        options.sock_state_cb_data = resolver;
        mask                       = ARES_OPT_SOCK_STATE_CB;
        if ((error = ares_init_options(&resolver->body.channel, &options, mask))) {
            uv_mutex_unlock(resolver->body.mutex_pending_queries);
            MVM_exception_throw_adhoc(tc,
                "Failed to configure a DNS resolution context: %s\n",
                ares_strerror(error));
        }
    }
    if (resolver->body.pending_queries_size == 0) {
        idx                                 = 0;
        resolver->body.pending_queries      = MVM_calloc(2, sizeof(MVMResolverQueryInfo *));
        resolver->body.pending_queries_size = 2;
    }
    else {
        size_t i;

        for (i = 0; i < resolver->body.pending_queries_size; ++i) {
            if (resolver->body.pending_queries[i] == NULL) {
                idx = i;
                break;
            }
        }
        assert(idx != -1);
        if (idx == resolver->body.pending_queries_size - 1) {
            size_t size = resolver->body.pending_queries_size * 2;
            resolver->body.pending_queries      = MVM_realloc(
                resolver->body.pending_queries, sizeof(MVMResolverQueryInfo *) * size);
            resolver->body.pending_queries_size = size;
            for (i = idx + 1; i < size; ++i)
                resolver->body.pending_queries[i] = NULL;
        }
    }
    resolver->body.pending_queries[idx] = qi;
    uv_mutex_unlock(resolver->body.mutex_pending_queries);

    /* Begin the query: */
    ares_query(resolver->body.channel, qi->question, qi->class, qi->type, get_answer, qi);
    /* poll_connection should get called at some point after this. */
}

static void query_cancel(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMResolverQueryInfo *qi = (MVMResolverQueryInfo *)data;
    finish_query(qi, 0);
}

static void query_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    MVMResolverQueryInfo *qi = (MVMResolverQueryInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &(qi->resolver));
}

static void query_gc_free(MVMThreadContext *tc, MVMObject *async_task, void *data) {
    if (data) {
        MVMResolverQueryInfo *qi = (MVMResolverQueryInfo *)data;
        MVM_free(qi->question);
        MVM_free(qi->handle);
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
