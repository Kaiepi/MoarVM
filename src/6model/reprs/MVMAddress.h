#ifdef _MSC_VER
typedef ULONG  in_addr_t;
typedef USHORT in_port_t;
typedef USHORT sa_family_t;
#else
#  define MVM_HAS_SOCKADDR_LEN
#endif

#ifndef _WIN32
#  include <sys/un.h>

#  define MVM_HAS_AF_UNIX
#  define MVM_SOCKADDR_UN_PATH_SIZE sizeof(((struct sockaddr_un *)NULL)->sun_path)
#endif

/* Representation used by VM-level network addresses. */
struct MVMAddressBody {
    /* The native address. */
    union {
        struct sockaddr_in  ip4;
        struct sockaddr_in6 ip6;
#ifdef MVM_HAS_AF_UNIX
        struct sockaddr_un  un;
#endif
        struct sockaddr     any;
    } storage;
};

struct MVMAddress {
    MVMObject      common;
    MVMAddressBody body;
};

const MVMREPROps * MVMAddress_initialize(MVMThreadContext *tc);

MVM_STATIC_INLINE socklen_t MVM_address_get_storage_length(MVMThreadContext *tc, const struct sockaddr *socket_address) {
#ifdef MVM_HAS_SOCKADDR_LEN
    return socket_address->sa_len;
#else
    switch (socket_address->sa_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
#  ifdef MVM_HAS_AF_UNIX
        case AF_UNIX: {
            const struct sockaddr_un *socket_address_un;
            size_t                    path_len;

            socket_address_un = (const struct sockaddr_un *)socket_address;
            for (path_len = MVM_SOCKADDR_UN_PATH_SIZE; path_len--;)
                if (socket_address_un[path_len] != '\0')
                    break;
            return sizeof(*socket_address_un) - MVM_SOCKADDR_UN_PATH_SIZE + path_len;
        }
#  endif
        default:
            MVM_exception_throw_adhoc(tc,
                "Unsupported native address family: %hhu",
                address->sa_family);
    }
#endif
}

MVM_STATIC_INLINE void MVM_address_set_storage_length(MVMThreadContext *tc, struct sockaddr *socket_address, socklen_t len) {
#ifdef MVM_HAS_SOCKADDR_LEN
    socket_address->sa_len = len;
#endif
}

MVMuint16 MVM_address_get_port(MVMThreadContext *tc, MVMAddress *address);
MVMuint32 MVM_address_get_scope_id(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_from_ipv4_literal(MVMThreadContext *tc, MVMString *literal, MVMuint16 port);
MVMObject * MVM_address_from_ipv6_literal(MVMThreadContext *tc, MVMString *literal, MVMuint16 port);
MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path);
MVMString * MVM_address_to_string(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_from_ipv4_address(MVMThreadContext *tc, MVMArray *address_buf, MVMuint16 port);
MVMObject * MVM_address_from_ipv6_address(MVMThreadContext *tc,
        MVMArray *address_buf, MVMuint16 port, MVMuint32 scope_id);
MVMObject * MVM_address_from_unix_address(MVMThreadContext *tc, MVMArray *address_buf);

#ifdef MVM_HAS_SOCKADDR_LEN
#  undef MVM_HAS_SOCKADDR_LEN
#endif
