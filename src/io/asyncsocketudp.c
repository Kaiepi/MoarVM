#include "moar.h"

/* Number of bytes we accept per read. */
#define CHUNK_SIZE 65536

/* Data that we keep for an asynchronous UDP socket handle. */
typedef struct {
    /* The libuv handle to the socket. */
    uv_udp_t *handle;
} MVMIOAsyncUDPSocketData;

/* Info we convey about a read task. */
typedef struct {
    MVMOSHandle      *handle;
    MVMObject        *buf_type;
    int               seq_number;
    MVMThreadContext *tc;
    int               work_idx;
} ReadInfo;

/* Allocates a buffer of the suggested size. */
static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    size_t size = suggested_size > 0 ? suggested_size : 4;
    buf->base   = MVM_malloc(size);
    buf->len    = size;
}

/* Callback used to simply free memory on close. */
static void free_on_close_cb(uv_handle_t *handle) {
    MVM_free(handle);
}

/* Read handler. */
static void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *native_address, unsigned flags) {
    ReadInfo         *ri  = (ReadInfo *)handle->data;
    MVMThreadContext *tc  = ri->tc;
    MVMObject        *arr;
    MVMAsyncTask     *t;

    /* libuv will call on_read once after all datagram read operations
     * to "give us back a buffer". in that case, nread and addr are NULL.
     * This is an artifact of the underlying implementation and we shouldn't
     * pass it through to the user. */

    if (nread == 0 && native_address == NULL)
        return;

    arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
    t = MVM_io_eventloop_get_active_work(tc, ri->work_idx);

    MVM_repr_push_o(tc, arr, t->body.schedulee);
    if (nread >= 0) {
        MVMROOT2(tc, t, arr, {
            /* Push the sequence number. */
            MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc,
                tc->instance->boot_types.BOOTInt, ri->seq_number++));

            /* Produce a buffer and push it. */
            {
                MVMArray *result = (MVMArray *)MVM_repr_alloc_init(tc, ri->buf_type);
                result->body.slots.i8 = (MVMint8 *)buf->base;
                result->body.start    = 0;
                result->body.ssize    = buf->len;
                result->body.elems    = nread;
                MVM_repr_push_o(tc, arr, (MVMObject *)result);
            }

            /* Produce an address family and address and push it. */
            {
                MVMAddress *address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
                MVMint64    family;
                switch (native_address->sa_family) {
                    case PF_INET:
                        family = MVM_PROTOCOL_FAMILY_INET;
                        memcpy(&address->body.storage, native_address, sizeof(struct sockaddr_in));
#ifndef MVM_HAS_SA_LEN
                        MVM_io_address_set_length(&address->body, sizeof(struct sockaddr_in));
#endif
                        break;
                    case PF_INET6:
                        family = MVM_PROTOCOL_FAMILY_INET6;
                        memcpy(&address->body.storage, native_address, sizeof(struct sockaddr_in6));
#ifndef MVM_HAS_SA_LEN
                        MVM_io_address_set_length(&address->body, sizeof(struct sockaddr_in6));
#endif
                        break;
                    default:
                        MVM_exception_throw_adhoc(tc,
                            "Unsupported native address family: %"PRIu16"",
                            (MVMuint16)native_address->sa_family);
                }
                MVMROOT(tc, address, {
                    MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, family));
                });
                MVM_repr_push_o(tc, arr, (MVMObject *)address);
            }

            /* No error. */
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
        });
    }
    else if (nread == UV_EOF) {
        MVMROOT2(tc, t, arr, {
            MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc,
                tc->instance->boot_types.BOOTInt, ri->seq_number));
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTAddress);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
        });
        if (buf->base)
            MVM_free(buf->base);
        uv_udp_recv_stop(handle);
        MVM_io_eventloop_remove_active_work(tc, &(ri->work_idx));
    }
    else {
        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTAddress);
        MVMROOT2(tc, t, arr, {
            MVMString *msg_str = MVM_string_ascii_decode_nt(tc,
                tc->instance->VMString, uv_strerror(nread));
            MVMObject *msg_box = MVM_repr_box_str(tc,
                tc->instance->boot_types.BOOTStr, msg_str);
            MVM_repr_push_o(tc, arr, msg_box);
        });
        if (buf->base)
            MVM_free(buf->base);
        uv_udp_recv_stop(handle);
        MVM_io_eventloop_remove_active_work(tc, &(ri->work_idx));
    }
    MVM_repr_push_o(tc, t->body.queue, arr);
}

/* Does setup work for setting up asynchronous reads. */
static void read_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMIOAsyncUDPSocketData *handle_data;
    int                   r;

    /* Add to work in progress. */
    ReadInfo *ri  = (ReadInfo *)data;
    ri->tc        = tc;
    ri->work_idx  = MVM_io_eventloop_add_active_work(tc, async_task);

    /* Start reading the stream. */
    handle_data = (MVMIOAsyncUDPSocketData *)ri->handle->body.data;
    handle_data->handle->data = data;
    if ((r = uv_udp_recv_start(handle_data->handle, on_alloc, on_read)) < 0) {
        /* Error; need to notify. */
        MVMROOT(tc, async_task, {
            MVMObject *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, ((MVMAsyncTask *)async_task)->body.schedulee);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTAddress);
            MVMROOT(tc, arr, {
                MVMString *msg_str = MVM_string_ascii_decode_nt(tc, tc->instance->VMString, uv_strerror(r));
                MVMObject *msg_box = MVM_repr_box_str(tc, tc->instance->boot_types.BOOTStr, msg_str);
                MVM_repr_push_o(tc, arr, msg_box);
            });
            MVM_repr_push_o(tc, ((MVMAsyncTask *)async_task)->body.queue, arr);
        });
    }
}

/* Marks objects for a read task. */
static void read_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    ReadInfo *ri = (ReadInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &ri->buf_type);
    MVM_gc_worklist_add(tc, worklist, &ri->handle);
}

/* Frees info for a read task. */
static void read_gc_free(MVMThreadContext *tc, MVMObject *t, void *data) {
    if (data)
        MVM_free(data);
}

/* Operations table for async read task. */
static const MVMAsyncTaskOps read_op_table = {
    read_setup,
    NULL,
    NULL,
    read_gc_mark,
    read_gc_free
};

static MVMAsyncTask * read_bytes(MVMThreadContext *tc, MVMOSHandle *h, MVMObject *queue,
                                 MVMObject *schedulee, MVMObject *buf_type, MVMObject *async_type) {
    MVMAsyncTask *task;
    ReadInfo    *ri;

    /* Validate REPRs. */
    if (REPR(queue)->ID != MVM_REPR_ID_ConcBlockingQueue)
        MVM_exception_throw_adhoc(tc,
            "asyncreadbytes target queue must have ConcBlockingQueue REPR (got %s)",
             MVM_6model_get_stable_debug_name(tc, queue->st));
    if (REPR(async_type)->ID != MVM_REPR_ID_MVMAsyncTask)
        MVM_exception_throw_adhoc(tc,
            "asyncreadbytes result type must have REPR AsyncTask");
    if (REPR(buf_type)->ID == MVM_REPR_ID_VMArray) {
        MVMint32 slot_type = ((MVMArrayREPRData *)STABLE(buf_type)->REPR_data)->slot_type;
        if (slot_type != MVM_ARRAY_U8 && slot_type != MVM_ARRAY_I8)
            MVM_exception_throw_adhoc(tc, "asyncreadbytes buffer type must be an array of uint8 or int8");
    }
    else {
        MVM_exception_throw_adhoc(tc, "asyncreadbytes buffer type must be an array");
    }

    /* Create async task handle. */
    MVMROOT4(tc, queue, schedulee, h, buf_type, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc, async_type);
    });
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.queue, queue);
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.schedulee, schedulee);
    task->body.ops  = &read_op_table;
    ri              = MVM_calloc(1, sizeof(ReadInfo));
    MVM_ASSIGN_REF(tc, &(task->common.header), ri->buf_type, buf_type);
    MVM_ASSIGN_REF(tc, &(task->common.header), ri->handle, h);
    task->body.data = ri;

    /* Hand the task off to the event loop. */
    MVMROOT(tc, task, {
        MVM_io_eventloop_queue_work(tc, (MVMObject *)task);
    });

    return task;
}

/* Info we convey about a write task. */
typedef struct {
    MVMOSHandle      *handle;
    MVMObject        *buf_data;
    uv_udp_send_t    *req;
    uv_buf_t          buf;
    MVMThreadContext *tc;
    int               work_idx;
    MVMAddress       *address;
} WriteInfo;

/* Completion handler for an asynchronous write. */
static void on_write(uv_udp_send_t *req, int status) {
    WriteInfo        *wi  = (WriteInfo *)req->data;
    MVMThreadContext *tc  = wi->tc;
    MVMObject        *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
    MVMAsyncTask     *t   = MVM_io_eventloop_get_active_work(tc, wi->work_idx);
    MVM_repr_push_o(tc, arr, t->body.schedulee);
    if (status >= 0) {
        MVMROOT2(tc, arr, t, {
            MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc,
                tc->instance->boot_types.BOOTInt, wi->buf.len));
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
        });
    }
    else {
        MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
        MVMROOT2(tc, arr, t, {
            MVMString *msg_str = MVM_string_ascii_decode_nt(tc,
                tc->instance->VMString, uv_strerror(status));
            MVMObject *msg_box = MVM_repr_box_str(tc,
                tc->instance->boot_types.BOOTStr, msg_str);
            MVM_repr_push_o(tc, arr, msg_box);
        });
    }
    MVM_repr_push_o(tc, t->body.queue, arr);
    MVM_free(wi->req);
    MVM_io_eventloop_remove_active_work(tc, &(wi->work_idx));
}

/* Does setup work for an asynchronous write. */
static void write_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    MVMIOAsyncUDPSocketData *handle_data;
    MVMArray                *buffer;
    char                    *output;
    int                      output_size, r;

    /* Add to work in progress. */
    WriteInfo *wi = (WriteInfo *)data;
    wi->tc        = tc;
    wi->work_idx  = MVM_io_eventloop_add_active_work(tc, async_task);

    /* Extract buf data. */
    buffer = (MVMArray *)wi->buf_data;
    output = (char *)(buffer->body.slots.i8 + buffer->body.start);
    output_size = (int)buffer->body.elems;

    /* Create and initialize write request. */
    wi->req       = MVM_malloc(sizeof(uv_udp_send_t));
    wi->req->data = data;
    wi->buf       = uv_buf_init(output, output_size);
    handle_data   = (MVMIOAsyncUDPSocketData *)wi->handle->body.data;

    if (uv_is_closing((uv_handle_t *)handle_data->handle)) {
        MVM_free(wi->req);
        MVM_exception_throw_adhoc(tc, "cannot write to a closed socket");
    }

    if ((r = uv_udp_send(wi->req, handle_data->handle, &(wi->buf), 1, &wi->address->body.storage.sa, on_write)) < 0) {
        /* Error; need to notify. */
        MVMROOT(tc, async_task, {
            MVMObject    *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, ((MVMAsyncTask *)async_task)->body.schedulee);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTInt);
            MVMROOT(tc, arr, {
                MVMString *msg_str = MVM_string_ascii_decode_nt(tc,
                    tc->instance->VMString, uv_strerror(r));
                MVMObject *msg_box = MVM_repr_box_str(tc,
                    tc->instance->boot_types.BOOTStr, msg_str);
                MVM_repr_push_o(tc, arr, msg_box);
            });
            MVM_repr_push_o(tc, ((MVMAsyncTask *)async_task)->body.queue, arr);
        });

        /* Cleanup handle. */
        MVM_free_null(wi->req);
        MVM_io_eventloop_remove_active_work(tc, &(wi->work_idx));
    }
}

/* Marks objects for a write task. */
static void write_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    WriteInfo *wi = (WriteInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &wi->handle);
    MVM_gc_worklist_add(tc, worklist, &wi->buf_data);
    MVM_gc_worklist_add(tc, worklist, &wi->address);
}

/* Frees info for a write task. */
static void write_gc_free(MVMThreadContext *tc, MVMObject *t, void *data) {
    if (data)
        MVM_free(data);
}

/* Operations table for async write task. */
static const MVMAsyncTaskOps write_op_table = {
    write_setup,
    NULL,
    NULL,
    write_gc_mark,
    write_gc_free
};

static MVMAsyncTask * write_bytes_to(MVMThreadContext *tc, MVMOSHandle *h, MVMObject *queue,
                                     MVMObject *schedulee, MVMObject *buffer, MVMObject *async_type,
                                     MVMAddress *address) {
    MVMAsyncTask    *task;
    WriteInfo       *wi;

    /* Validate REPRs. */
    if (REPR(queue)->ID != MVM_REPR_ID_ConcBlockingQueue)
        MVM_exception_throw_adhoc(tc,
            "asyncwritebytesto target queue must have ConcBlockingQueue REPR");
    if (REPR(async_type)->ID != MVM_REPR_ID_MVMAsyncTask)
        MVM_exception_throw_adhoc(tc,
            "asyncwritebytesto result type must have REPR AsyncTask");
    if (!IS_CONCRETE(buffer) || REPR(buffer)->ID != MVM_REPR_ID_VMArray)
        MVM_exception_throw_adhoc(tc, "asyncwritebytesto requires a native array to read from");
    if (((MVMArrayREPRData *)STABLE(buffer)->REPR_data)->slot_type != MVM_ARRAY_U8
        && ((MVMArrayREPRData *)STABLE(buffer)->REPR_data)->slot_type != MVM_ARRAY_I8)
        MVM_exception_throw_adhoc(tc, "asyncwritebytesto requires a native array of uint8 or int8");

    /* Resolve destination and create async task handle. */
    MVMROOT4(tc, queue, schedulee, async_type, buffer, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc, async_type);
    });
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.queue, queue);
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.schedulee, schedulee);
    task->body.ops  = &write_op_table;
    wi              = MVM_calloc(1, sizeof(WriteInfo));
    MVM_ASSIGN_REF(tc, &(task->common.header), wi->handle, h);
    MVM_ASSIGN_REF(tc, &(task->common.header), wi->buf_data, buffer);
    MVM_ASSIGN_REF(tc, &(task->common.header), wi->address, address);
    task->body.data = wi;

    /* Hand the task off to the event loop. */
    MVMROOT(tc, task, {
        MVM_io_eventloop_queue_work(tc, (MVMObject *)task);
    });

    return task;
}

/* Does an asynchronous close (since it must run on the event loop). */
static void close_perform(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    uv_handle_t *handle = (uv_handle_t *)data;

    if (uv_is_closing(handle))
        MVM_exception_throw_adhoc(tc, "cannot close a closed socket");

    uv_close(handle, free_on_close_cb);
}

/* Operations table for async close task. */
static const MVMAsyncTaskOps close_op_table = {
    close_perform,
    NULL,
    NULL,
    NULL,
    NULL
};

static MVMint64 close_socket(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOAsyncUDPSocketData *data = (MVMIOAsyncUDPSocketData *)h->body.data;
    MVMAsyncTask *task;

    MVMROOT(tc, h, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc,
            tc->instance->boot_types.BOOTAsync);
    });
    task->body.ops  = &close_op_table;
    task->body.data = data->handle;
    MVM_io_eventloop_queue_work(tc, (MVMObject *)task);

    return 0;
}

static MVMObject * get_socket_address(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOAsyncUDPSocketData *data;
    MVMAddress              *address;
    int                      len;
    int                      error;

    data    = (MVMIOAsyncUDPSocketData *)h->body.data;
    address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
    error   = uv_udp_getsockname(data->handle, &address->body.storage.sa, &len);
    if (error)
        MVM_exception_throw_adhoc(tc, "Error getting the local address of a socket: %s", uv_strerror(error));
    else {
        MVMObject *arr;
#ifndef MVM_HAS_SA_LEN
        MVM_io_address_set_length(&address->body, len);
#endif
        arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVMROOT(tc, arr, {
            sa_family_t family;

            switch (family = MVM_io_address_get_family(&address->body)) {
                case PF_INET:
                    family = MVM_PROTOCOL_FAMILY_INET;
                    break;
                case PF_INET6:
                    family = MVM_PROTOCOL_FAMILY_INET6;
                    break;
                case PF_UNIX:
                    family = MVM_PROTOCOL_FAMILY_UNIX;
                    break;
                default:
                    MVM_exception_throw_adhoc(tc, "Unknown native address family: %"PRIu16"", (MVMuint16)family);
            }

            MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, (MVMint64)family));
        });
        MVM_repr_push_o(tc, arr, (MVMObject *)address);
        return arr;
    }
}

static MVMObject * get_peer_address(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOAsyncUDPSocketData *data;
    MVMAddress              *address;
    int                      len;
    int                      error;

    data    = (MVMIOAsyncUDPSocketData *)h->body.data;
    address = (MVMAddress *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTAddress);
    error   = uv_udp_getpeername(data->handle, &address->body.storage.sa, &len);
    if (error)
        MVM_exception_throw_adhoc(tc, "Error getting the remote address of a socket: %s", uv_strerror(error));
    else {
        MVMObject *arr;
#ifndef MVM_HAS_SA_LEN
        MVM_io_address_set_length(&address->body, len);
#endif
        arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
        MVMROOT(tc, arr, {
            sa_family_t family;

            switch (family = MVM_io_address_get_family(&address->body)) {
                case PF_INET:
                    family = MVM_PROTOCOL_FAMILY_INET;
                    break;
                case PF_INET6:
                    family = MVM_PROTOCOL_FAMILY_INET6;
                    break;
                case PF_UNIX:
                    family = MVM_PROTOCOL_FAMILY_UNIX;
                    break;
                default:
                    MVM_exception_throw_adhoc(tc, "Unknown native address family: %"PRIu16"", (MVMuint16)family);
            }

            MVM_repr_push_o(tc, arr, MVM_repr_box_int(tc, tc->instance->boot_types.BOOTInt, (MVMint64)family));
        });
        MVM_repr_push_o(tc, arr, (MVMObject *)address);
        return arr;
    }
}

static MVMint64 socket_is_tty(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOAsyncUDPSocketData *data   = (MVMIOAsyncUDPSocketData *)h->body.data;
    uv_handle_t             *handle = (uv_handle_t *)data->handle;
    return (MVMint64)(handle->type == UV_TTY);
}

static MVMint64 socket_handle(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOAsyncUDPSocketData *data   = (MVMIOAsyncUDPSocketData *)h->body.data;
    uv_handle_t             *handle = (uv_handle_t *)data->handle;
    int        fd;
    uv_os_fd_t fh;

    uv_fileno(handle, &fh);
    fd = uv_open_osfhandle(fh);
    return (MVMint64)fd;
}

/* IO ops table, populated with functions. */
static const MVMIOClosable        closable          = { close_socket };
static const MVMIOAsyncReadable   async_readable    = { read_bytes };
static const MVMIOAsyncWritableTo async_writable_to = { write_bytes_to };
static const MVMIOAddressable     addressable       = { get_socket_address,
                                                        get_peer_address };
static const MVMIOIntrospection   introspection     = { socket_is_tty,
                                                        socket_handle };
static const MVMIOOps op_table = {
    &closable,
    NULL,
    NULL,
    &async_readable,
    NULL,
    &async_writable_to,
    NULL,
    NULL,
    &addressable,
    NULL,
    NULL,
    &introspection,
    NULL,
    NULL,
    NULL
};

/* Info we convey about a socket setup task. */
typedef struct {
    MVMAddress *address;
    MVMint64    flags;
} SocketSetupInfo;

/* Initilalize the UDP socket on the event loop. */
static void setup_setup(MVMThreadContext *tc, uv_loop_t *loop, MVMObject *async_task, void *data) {
    /* Set up the UDP handle. */
    SocketSetupInfo *ssi;
    uv_udp_t        *udp_handle;
    int              r;

    ssi        = (SocketSetupInfo *)data;
    udp_handle = MVM_malloc(sizeof(uv_udp_t));
    if ((r = uv_udp_init(loop, udp_handle)) >= 0) {
        if (ssi->address)
            r = uv_udp_bind(udp_handle, &ssi->address->body.storage.sa, 0);
        if (r >= 0 && (ssi->flags & 1))
            r = uv_udp_set_broadcast(udp_handle, 1);
    }

    if (r >= 0) {
        /* UDP handle initialized; wrap it up in an I/O handle and send. */
        MVMAsyncTask *t   = (MVMAsyncTask *)async_task;
        MVMObject    *arr;
        MVMROOT(tc, t, {
            arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVM_repr_push_o(tc, arr, t->body.schedulee);
            MVMROOT(tc, arr, {
                MVMOSHandle             *result = (MVMOSHandle *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTIO);
                MVMIOAsyncUDPSocketData *data   = MVM_calloc(1, sizeof(MVMIOAsyncUDPSocketData));
                data->handle      = udp_handle;
                result->body.ops  = &op_table;
                result->body.data = data;
                MVM_repr_push_o(tc, arr, (MVMObject *)result);
            });
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTStr);
        });
        MVM_repr_push_o(tc, t->body.queue, arr);
    }
    else {
        /* Something failed; need to notify. */
        MVMROOT(tc, async_task, {
            MVMObject    *arr = MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTArray);
            MVMAsyncTask *t   = (MVMAsyncTask *)async_task;
            MVM_repr_push_o(tc, arr, t->body.schedulee);
            MVM_repr_push_o(tc, arr, tc->instance->boot_types.BOOTIO);
            MVMROOT2(tc, arr, t, {
                MVMString *msg_str = MVM_string_ascii_decode_nt(tc,
                    tc->instance->VMString, uv_strerror(r));
                MVMObject *msg_box = MVM_repr_box_str(tc,
                    tc->instance->boot_types.BOOTStr, msg_str);
                MVM_repr_push_o(tc, arr, msg_box);
            });
            MVM_repr_push_o(tc, t->body.queue, arr);
            uv_close((uv_handle_t *)udp_handle, free_on_close_cb);
        });
    }
}

/* Marks objects for a setup task. */
static void setup_gc_mark(MVMThreadContext *tc, void *data, MVMGCWorklist *worklist) {
    SocketSetupInfo *ssi = (SocketSetupInfo *)data;
    MVM_gc_worklist_add(tc, worklist, &ssi->address);
}

/* Frees info for a setup task. */
static void setup_gc_free(MVMThreadContext *tc, MVMObject *t, void *data) {
    if (data)
        MVM_free(data);
}

/* Operations table for setup task. */
static const MVMAsyncTaskOps setup_op_table = {
    setup_setup,
    NULL,
    NULL,
    setup_gc_mark,
    setup_gc_free
};

/* Creates a UDP socket and binds it to the specified host/port. */
MVMObject * MVM_io_socket_udp_async(MVMThreadContext *tc, MVMObject *queue,
                                    MVMObject *schedulee, MVMObject *address,
                                    MVMint64 flags, MVMObject *async_type) {
    MVMAsyncTask    *task;
    SocketSetupInfo *ssi;
    int              address_is_null;

    /* Validate REPRs. */
    if (REPR(queue)->ID != MVM_REPR_ID_ConcBlockingQueue)
        MVM_exception_throw_adhoc(tc,
            "asyncudp target queue must have ConcBlockingQueue REPR");
    if (REPR(async_type)->ID != MVM_REPR_ID_MVMAsyncTask)
        MVM_exception_throw_adhoc(tc,
            "asyncudp result type must have REPR AsyncTask");
    if (!(address_is_null = MVM_is_null(tc, address)) && (REPR(address)->ID != MVM_REPR_ID_MVMAddress || !IS_CONCRETE(address)))
        MVM_exception_throw_adhoc(tc,
            "asyncudp address must either be null or be a concrete object of REPR MVMAddress");

    /* Create async task handle. */
    MVMROOT2(tc, queue, schedulee, {
        task = (MVMAsyncTask *)MVM_repr_alloc_init(tc, async_type);
    });
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.queue, queue);
    MVM_ASSIGN_REF(tc, &(task->common.header), task->body.schedulee, schedulee);
    task->body.ops  = &setup_op_table;
    ssi             = MVM_calloc(1, sizeof(SocketSetupInfo));
    MVM_ASSIGN_REF(tc, &(task->common.header), ssi->address, address_is_null ? NULL : address);
    ssi->flags      = flags;
    task->body.data = ssi;

    /* Hand the task off to the event loop. */
    MVMROOT(tc, task, {
        MVM_io_eventloop_queue_work(tc, (MVMObject *)task);
    });

    return (MVMObject *)task;
}
