#define MVM_SOCKET_FAMILY_UNSPEC 0
#define MVM_SOCKET_FAMILY_INET   1
#define MVM_SOCKET_FAMILY_INET6  2
#define MVM_SOCKET_FAMILY_UNIX   3

#define MVM_SOCKET_TYPE_ANY       0
#define MVM_SOCKET_TYPE_STREAM    1
#define MVM_SOCKET_TYPE_DGRAM     2
#define MVM_SOCKET_TYPE_RAW       3
#define MVM_SOCKET_TYPE_RDM       4
#define MVM_SOCKET_TYPE_SEQPACKET 5

#define MVM_SOCKET_PROTOCOL_ANY 0
#define MVM_SOCKET_PROTOCOL_TCP 1
#define MVM_SOCKET_PROTOCOL_UDP 2

sa_family_t MVM_address_to_native_family(MVMThreadContext *tc, MVMint64 family);
MVMint64    MVM_address_from_native_family(MVMThreadContext *tc, sa_family_t family);
int         MVM_address_to_native_type(MVMThreadContext *tc, MVMint64 type);
MVMint64    MVM_address_from_native_type(MVMThreadContext *tc, int type);
int         MVM_address_to_native_protocol(MVMThreadContext *tc, MVMint64 protocol);
MVMint64    MVM_address_from_native_protocol(MVMThreadContext *tc, int protocol);

MVMuint16 MVM_address_port(MVMThreadContext *tc, MVMAddress *address);
MVMuint32 MVM_address_flowinfo(MVMThreadContext *tc, MVMAddress *address);
MVMuint32 MVM_address_scope_id(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_from_ipv4_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port);
MVMObject * MVM_address_from_ipv6_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port, MVMuint32 flowinfo, MVMuint32 scope_id);
MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path);
MVMString * MVM_address_to_presentation(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_resolve_sync(MVMThreadContext *tc,
        MVMString *host, MVMuint16 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive);
