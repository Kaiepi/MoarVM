#include "moar.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2def.h>
    #include <ws2tcpip.h>
    #include <io.h>

    typedef SOCKET Socket;
    #define sa_family_t unsigned int
    #define isatty _isatty
#else
    #include "unistd.h"
    #include <netinet/tcp.h>
    #include <sys/socket.h>
    #include <sys/un.h>

    typedef int Socket;
    #define closesocket close
#endif

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

/* Assumed maximum packet size. If ever changing this to something beyond a
 * 16-bit number, then make sure to change the receive offsets in the data
 * structure below. */
#define PACKET_SIZE 65535

/* Error handling varies between POSIX and WinSock. */
MVM_NO_RETURN static void throw_error(MVMThreadContext *tc, int r, char *operation) MVM_NO_RETURN_ATTRIBUTE;
#ifdef _WIN32
    #define MVM_IS_SOCKET_ERROR(x) ((x) == SOCKET_ERROR)
    static void throw_error(MVMThreadContext *tc, int r, char *operation) {
        int error = WSAGetLastError();
        LPTSTR error_string = NULL;
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, error, 0, (LPTSTR)&error_string, 0, NULL) == 0) {
            /* Couldn't get error string; throw with code. */
            MVM_exception_throw_adhoc(tc, "Could not %s: error code %d", operation, error);
        }
        MVM_exception_throw_adhoc(tc, "Could not %s: %s", operation, error_string);
    }
#else
    #define MVM_IS_SOCKET_ERROR(x) ((x) < 0)
    static void throw_error(MVMThreadContext *tc, int r, char *operation) {
        MVM_exception_throw_adhoc(tc, "Could not %s: %s", operation, strerror(errno));
    }
#endif

 /* Data that we keep for a socket-based handle. */
typedef struct {
    /* The socket handle (file descriptor on POSIX, SOCKET on Windows). */
    Socket handle;

    /* Buffer of the last received packet of data, and start/end pointers
     * into the data. */
    char *last_packet;
    MVMuint16 last_packet_start;
    MVMuint16 last_packet_end;

    /* Did we reach EOF yet? */
    MVMint32 eof;

    /* ID for instrumentation. */
    unsigned int interval_id;
} MVMIOSyncSocketData;

/* Read a packet worth of data into the last packet buffer. */
static void read_one_packet(MVMThreadContext *tc, MVMIOSyncSocketData *data) {
    unsigned int interval_id = MVM_telemetry_interval_start(tc, "syncsocket.read_one_packet");
    int r;
    data->last_packet = MVM_malloc(PACKET_SIZE);
    do {
        MVM_gc_mark_thread_blocked(tc);
        r = recv(data->handle, data->last_packet, PACKET_SIZE, 0);
        MVM_gc_mark_thread_unblocked(tc);
    } while(r == -1 && errno == EINTR);
    MVM_telemetry_interval_stop(tc, interval_id, "syncsocket.read_one_packet");
    if (MVM_IS_SOCKET_ERROR(r) || r == 0) {
        MVM_free(data->last_packet);
        data->last_packet = NULL;
        if (r != 0)
            throw_error(tc, r, "receive data from socket");
    }
    else {
        data->last_packet_start = 0;
        data->last_packet_end = r;
    }
}

MVMint64 socket_read_bytes(MVMThreadContext *tc, MVMOSHandle *h, char **buf, MVMint64 bytes) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    char *use_last_packet = NULL;
    MVMuint16 use_last_packet_start, use_last_packet_end;

    /* If at EOF, nothing more to do. */
    if (data->eof) {
        *buf = NULL;
        return 0;
    }

    /* See if there's anything in the packet buffer. */
    if (data->last_packet) {
        MVMuint16 last_remaining = data->last_packet_end - data->last_packet_start;
        if (bytes <= last_remaining) {
            /* There's enough, and it's sufficient for the request. Extract it
             * and return, discarding the last packet buffer if we drain it. */
            *buf = MVM_malloc(bytes);
            memcpy(*buf, data->last_packet + data->last_packet_start, bytes);
            if (bytes == last_remaining) {
                MVM_free(data->last_packet);
                data->last_packet = NULL;
            }
            else {
                data->last_packet_start += bytes;
            }
            return bytes;
        }
        else {
            /* Something, but not enough. Take the last packet for use, then
             * we'll read another one. */
            use_last_packet = data->last_packet;
            use_last_packet_start = data->last_packet_start;
            use_last_packet_end = data->last_packet_end;
            data->last_packet = NULL;
        }
    }

    /* If we get here, we need to read another packet. */
    read_one_packet(tc, data);

    /* Now assemble the result. */
    if (data->last_packet && use_last_packet) {
        /* Need to assemble it from two places. */
        MVMuint32 last_available = use_last_packet_end - use_last_packet_start;
        MVMuint32 available = last_available + data->last_packet_end;
        if (bytes > available)
            bytes = available;
        *buf = MVM_malloc(bytes);
        memcpy(*buf, use_last_packet + use_last_packet_start, last_available);
        memcpy(*buf + last_available, data->last_packet, bytes - last_available);
        if (bytes == available) {
            /* We used all of the just-read packet. */
            MVM_free(data->last_packet);
            data->last_packet = NULL;
        }
        else {
            /* Still something left in the just-read packet for next time. */
            data->last_packet_start += bytes - last_available;
        }
    }
    else if (data->last_packet) {
        /* Only data from the just-read packet. */
        if (bytes >= data->last_packet_end) {
            /* We need all of it, so no copying needed, just hand it back. */
            *buf = data->last_packet;
            bytes = data->last_packet_end;
            data->last_packet = NULL;
        }
        else {
            /* Only need some of it. */
            *buf = MVM_malloc(bytes);
            memcpy(*buf, data->last_packet, bytes);
            data->last_packet_start += bytes;
        }
    }
    else if (use_last_packet) {
        /* Nothing read this time, so at the end. Drain previous packet data
         * and mark EOF. */
        bytes = use_last_packet_end - use_last_packet_start;
        *buf = MVM_malloc(bytes);
        memcpy(*buf, use_last_packet + use_last_packet_start, bytes);
        data->eof = 1;
    }
    else {
        /* Nothing to hand back; at EOF. */
        *buf = NULL;
        bytes = 0;
        data->eof = 1;
    }

    return bytes;
}

/* Checks if EOF has been reached on the incoming data. */
MVMint64 socket_eof(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    return data->eof;
}

void socket_flush(MVMThreadContext *tc, MVMOSHandle *h, MVMint32 sync) {
    /* A no-op for sockets; we don't buffer. */
}

void socket_truncate(MVMThreadContext *tc, MVMOSHandle *h, MVMint64 bytes) {
    MVM_exception_throw_adhoc(tc, "Cannot truncate a socket");
}

/* Writes the specified bytes to the stream. */
MVMint64 socket_write_bytes(MVMThreadContext *tc, MVMOSHandle *h, char *buf, MVMint64 bytes) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    MVMint64 sent = 0;
    unsigned int interval_id;

    interval_id = MVM_telemetry_interval_start(tc, "syncsocket.write_bytes");
    MVM_gc_mark_thread_blocked(tc);
    while (bytes > 0) {
        int r;
        do {
            r = send(data->handle, buf, (int)bytes, 0);
        } while(r == -1 && errno == EINTR);
        if (MVM_IS_SOCKET_ERROR(r)) {
            MVM_gc_mark_thread_unblocked(tc);
            MVM_telemetry_interval_stop(tc, interval_id, "syncsocket.write_bytes");
            throw_error(tc, r, "send data to socket");
        }
        sent += r;
        buf += r;
        bytes -= r;
    }
    MVM_gc_mark_thread_unblocked(tc);
    MVM_telemetry_interval_annotate(bytes, interval_id, "written this many bytes");
    MVM_telemetry_interval_stop(tc, interval_id, "syncsocket.write_bytes");
    return bytes;
}

static MVMint64 do_close(MVMThreadContext *tc, MVMIOSyncSocketData *data) {
    if (data->handle) {
        closesocket(data->handle);
        data->handle = 0;
    }
    return 0;
}
static MVMint64 close_socket(MVMThreadContext *tc, MVMOSHandle *h) {
    return do_close(tc, (MVMIOSyncSocketData *)h->body.data);
}

static void gc_free(MVMThreadContext *tc, MVMObject *h, void *d) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)d;
    do_close(tc, data);
    MVM_free(data);
}

static size_t get_struct_size_for_family(sa_family_t family) {
    switch (family) {
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        case AF_INET:
            return sizeof(struct sockaddr_in);
#ifndef _WIN32
        case AF_UNIX:
            return sizeof(struct sockaddr_un);
#endif
        default:
            return sizeof(struct sockaddr);
    }
}

/* This function may return any type of sockaddr e.g. sockaddr_un, sockaddr_in or sockaddr_in6
 * It shouldn't be a problem with general code as long as the port number is kept below the int16 limit: 65536
 * After this it defines the family which may spawn non internet sockaddr's
 * The family can be extracted by (port >> 16) & USHORT_MAX
 *
 * Currently supported families:
 *
 * AF_UNSPEC = 1
 *   Unspecified, in most cases should be equal to AF_INET or AF_INET6
 *
 * AF_UNIX = 1
 *   Unix domain socket, will spawn a sockaddr_un which will use the given host as path
 *   e.g: MVM_io_resolve_host_name(tc, "/run/moarvm.sock", 1 << 16)
 *   will spawn an unix domain socket on /run/moarvm.sock
 *
 * AF_INET = 2
 *   IPv4 socket
 *
 * AF_INET6 = 10
 *   IPv6 socket
 */
struct sockaddr * MVM_io_resolve_host_name(MVMThreadContext *tc, MVMString *host, MVMint64 port) {
    char *host_cstr = MVM_string_utf8_encode_C_string(tc, host);
    struct sockaddr *dest;
    int error;
    struct addrinfo *result;
    char port_cstr[8];
    unsigned short family = (port >> 16) & USHRT_MAX;
    struct addrinfo hints;

#ifndef _WIN32
    /* AF_UNIX = 1 */
    if (family == AF_UNIX) {
        struct sockaddr_un *result_un = MVM_malloc(sizeof(struct sockaddr_un));

        if (strlen(host_cstr) > 107) {
            MVM_free(result_un);
            MVM_free(host_cstr);
            MVM_exception_throw_adhoc(tc, "Socket path can only be maximal 107 characters long");
        }

        result_un->sun_family = AF_UNIX;
        strcpy(result_un->sun_path, host_cstr);
        MVM_free(host_cstr);

        return (struct sockaddr *)result_un;
    }
#endif

    hints.ai_family = family;
    hints.ai_socktype = 0;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_addr = NULL;
    hints.ai_canonname = NULL;
    hints.ai_next = NULL;

    snprintf(port_cstr, 8, "%d", (int)port);

    MVM_gc_mark_thread_blocked(tc);
    error = getaddrinfo(host_cstr, port_cstr, &hints, &result);
    MVM_gc_mark_thread_unblocked(tc);
    if (error == 0) {
        size_t size = get_struct_size_for_family(result->ai_addr->sa_family);
        MVM_free(host_cstr);
        dest = MVM_malloc(size);
        memcpy(dest, result->ai_addr, size);
    }
    else {
        char *waste[] = { host_cstr, NULL };
        MVM_exception_throw_adhoc_free(tc, waste, "Failed to resolve host name '%s' with family %d. Error: '%s'",
                                       host_cstr, family, gai_strerror(error));
    }
    freeaddrinfo(result);

    return dest;
}

/* Establishes a connection. */
static void socket_connect(MVMThreadContext *tc, MVMOSHandle *h, MVMString *host, MVMint64 port) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    unsigned int interval_id;

    interval_id = MVM_telemetry_interval_start(tc, "syncsocket connect");
    if (!data->handle) {
        struct sockaddr *dest = MVM_io_resolve_host_name(tc, host, port);
        int r;

        Socket s = socket(dest->sa_family , SOCK_STREAM , 0);
        if (MVM_IS_SOCKET_ERROR(s)) {
            MVM_free(dest);
            MVM_telemetry_interval_stop(tc, interval_id, "syncsocket connect");
            throw_error(tc, s, "create socket");
        }

        do {
            MVM_gc_mark_thread_blocked(tc);
            r = connect(s, dest, (socklen_t)get_struct_size_for_family(dest->sa_family));
            MVM_gc_mark_thread_unblocked(tc);
        } while(r == -1 && errno == EINTR);
        MVM_free(dest);
        if (MVM_IS_SOCKET_ERROR(r)) {
            MVM_telemetry_interval_stop(tc, interval_id, "syncsocket connect");
            throw_error(tc, s, "connect socket");
        }

        data->handle = s;
    }
    else {
        MVM_telemetry_interval_stop(tc, interval_id, "syncsocket didn't connect");
        MVM_exception_throw_adhoc(tc, "Socket is already bound or connected");
    }
}

static void socket_bind(MVMThreadContext *tc, MVMOSHandle *h, MVMString *host, MVMint64 port, MVMint32 backlog) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    if (!data->handle) {
        struct sockaddr *dest = MVM_io_resolve_host_name(tc, host, port);
        int r;

        Socket s = socket(dest->sa_family , SOCK_STREAM , 0);
        if (MVM_IS_SOCKET_ERROR(s)) {
            MVM_free(dest);
            throw_error(tc, s, "create socket");
        }

        /* On POSIX, we set the SO_REUSEADDR option, which allows re-use of
         * a port in TIME_WAIT state (modulo many hair details). Oringinally,
         * MoarVM used libuv, which does this automatically on non-Windows.
         * We have tests with bring up a server, then take it down, and then
         * bring another up on the same port, and we get test failures due
         * to racing to re-use the port without this. */
#ifndef _WIN32
        {
            int one = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        }
#endif

        r = bind(s, dest, (socklen_t)get_struct_size_for_family(dest->sa_family));
        MVM_free(dest);
        if (MVM_IS_SOCKET_ERROR(r))
            throw_error(tc, s, "bind socket");

        r = listen(s, (int)backlog);
        if (MVM_IS_SOCKET_ERROR(r))
            throw_error(tc, s, "start listening on socket");

        data->handle = s;
    }
    else {
        MVM_exception_throw_adhoc(tc, "Socket is already bound or connected");
    }
}

MVMint64 socket_getport(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;

    struct sockaddr_storage name;
    int error;
    socklen_t len = sizeof(struct sockaddr_storage);
    MVMint64 port = 0;

    error = getsockname(data->handle, (struct sockaddr *) &name, &len);

    if (error != 0)
        MVM_exception_throw_adhoc(tc, "Failed to getsockname: %s", strerror(errno));

    switch (name.ss_family) {
        case AF_INET6:
            port = ntohs((*( struct sockaddr_in6 *) &name).sin6_port);
            break;
        case AF_INET:
            port = ntohs((*( struct sockaddr_in *) &name).sin_port);
            break;
    }

    return port;
}

static MVMObject * socket_accept(MVMThreadContext *tc, MVMOSHandle *h);

static MVMint64 socket_is_tty(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    return (MVMint64)isatty(data->handle);
}

static MVMint64 socket_handle(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    return (MVMint64)data->handle;
}

static MVMint64 get_sock_opt(MVMThreadContext *tc, MVMOSHandle *h, MVMint32 option) {
    MVMIOSyncSocketData *data   = (MVMIOSyncSocketData *)h->body.data;
    Socket               s      = data->handle;
    socklen_t            len;
    int                  e;
    MVMint64             output;

    if (s < 0)
        MVM_exception_throw_adhoc(tc, "Cannot get socket options from invalid sockets with a fd of %d", s);

    switch (option) {
        case SO_BROADCAST:
        case SO_KEEPALIVE:
        case SO_REUSEADDR:
        case SO_DONTROUTE:
        case SO_SNDBUF:
        case SO_RCVBUF:
        case SO_OOBINLINE: {
            int input;
            len = sizeof(int);
            e = getsockopt(s, SOL_SOCKET, option, (char *)&input, &len);
            output = input;
            break;
        }
        case SO_LINGER: {
            struct linger input;
            len = sizeof(struct linger);
            e = getsockopt(s, SOL_SOCKET, option, (char *)&input, &len);
            output = input.l_onoff ? input.l_linger : -1;
            break;
        }
        case TCP_NODELAY: {
            int input;
            len = sizeof(int);
            e = getsockopt(s, IPPROTO_TCP, option, (char *)&input, &len);
            output = input;
            break;
        }
        default:
            MVM_exception_throw_adhoc(tc, "This socket option is not supported by MoarVM: %d\n", (int)option);
            break;
    }

    if (e < 0) {
        MVM_exception_throw_adhoc(tc, "Failed to get socket option %s from socket %d: %s",
                MVM_io_get_sockopt_name(option), s, strerror(errno));
    }

    return output;
}

static void set_sock_opt(MVMThreadContext *tc, MVMOSHandle *h, MVMint32 option, MVMint64 value) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    Socket               s    = data->handle;
    int                  e;

    if (s < 0)
        MVM_exception_throw_adhoc(tc, "Cannot set socket options on invalid sockets with an fd of %d", s);

    switch (option) {
        case SO_BROADCAST:
        case SO_KEEPALIVE:
        case SO_REUSEADDR:
        case SO_DONTROUTE:
        case SO_SNDBUF:
        case SO_RCVBUF:
        case SO_OOBINLINE: {
            int input = value;
            e = setsockopt(s, SOL_SOCKET, option, (char *)&input, sizeof(input));
            break;
        }
        case SO_LINGER: {
            struct linger input = { ((value < 0) ? 0 : 1), ((value < 0) ? 0 : value) };
            e = setsockopt(s, SOL_SOCKET, option, (char *)&input, sizeof(input));
            break;
        }
        case TCP_NODELAY: {
            int input = value;
            e = setsockopt(s, IPPROTO_TCP, option, (char *)&input, sizeof(input));
            break;
        }
        default:
            MVM_exception_throw_adhoc(tc, "This socket option is not supported by MoarVM: %d\n", (int)option);
            break;
    }

    if (e < 0) {
        MVM_exception_throw_adhoc(tc, "Failed to set socket option %s for socket %d: %s",
                MVM_io_get_sockopt_name(option), s, strerror(errno));
    }
}

/* IO ops table, populated with functions. */
static const MVMIOClosable      closable      = { close_socket };
static const MVMIOSyncReadable  sync_readable = { socket_read_bytes,
                                                  socket_eof };
static const MVMIOSyncWritable  sync_writable = { socket_write_bytes,
                                                  socket_flush,
                                                  socket_truncate };
static const MVMIOSockety       sockety       = { socket_connect,
                                                  socket_bind,
                                                  socket_accept,
                                                  socket_getport };
static const MVMIOIntrospection introspection = { socket_is_tty,
                                                  socket_handle };
static const MVMIOOptions       options       = { get_sock_opt,
                                                  set_sock_opt };
static const MVMIOOps op_table = {
    &closable,
    &sync_readable,
    &sync_writable,
    NULL,
    NULL,
    NULL,
    NULL,
    &sockety,
    NULL,
    NULL,
    &introspection,
    &options,
    NULL,
    NULL,
    gc_free
};

static MVMObject * socket_accept(MVMThreadContext *tc, MVMOSHandle *h) {
    MVMIOSyncSocketData *data = (MVMIOSyncSocketData *)h->body.data;
    Socket s;

    unsigned int interval_id = MVM_telemetry_interval_start(tc, "syncsocket accept");
    do {
        MVM_gc_mark_thread_blocked(tc);
        s = accept(data->handle, NULL, NULL);
        MVM_gc_mark_thread_unblocked(tc);
    } while(s == -1 && errno == EINTR);
    if (MVM_IS_SOCKET_ERROR(s)) {
        MVM_telemetry_interval_stop(tc, interval_id, "syncsocket accept failed");
        throw_error(tc, s, "accept socket connection");
    }
    else {
        MVMOSHandle * const result = (MVMOSHandle *)MVM_repr_alloc_init(tc,
                tc->instance->boot_types.BOOTIO);
        MVMIOSyncSocketData * const data = MVM_calloc(1, sizeof(MVMIOSyncSocketData));
        data->handle = s;
        result->body.ops  = &op_table;
        result->body.data = data;
        MVM_telemetry_interval_stop(tc, interval_id, "syncsocket accept succeeded");
        return (MVMObject *)result;
    }
}

MVMObject * MVM_io_socket_create(MVMThreadContext *tc, MVMint64 listen) {
    MVMOSHandle         * const result = (MVMOSHandle *)MVM_repr_alloc_init(tc, tc->instance->boot_types.BOOTIO);
    MVMIOSyncSocketData * const data   = MVM_calloc(1, sizeof(MVMIOSyncSocketData));
    result->body.ops  = &op_table;
    result->body.data = data;
    return (MVMObject *)result;
}

MVMString * MVM_io_get_hostname(MVMThreadContext *tc) {
    char hostname[UV_MAXHOSTNAMESIZE];
    size_t size = UV_MAXHOSTNAMESIZE;
    int result = uv_os_gethostname(hostname, &size);

    if(result < 0) {
        MVM_exception_throw_adhoc(tc, "Failed to get hostname: %i", result);
    }

    return MVM_string_ascii_decode_nt(tc, tc->instance->VMString, hostname);
}
