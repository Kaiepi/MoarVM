#define MVM_PROTOCOL_FAMILY_UNSPEC 0
#define MVM_PROTOCOL_FAMILY_INET   1
#define MVM_PROTOCOL_FAMILY_INET6  2
#define MVM_PROTOCOL_FAMILY_UNIX   3

#define MVM_SOCKET_TYPE_ANY       0
#define MVM_SOCKET_TYPE_STREAM    1
#define MVM_SOCKET_TYPE_DGRAM     2
#define MVM_SOCKET_TYPE_RAW       3
#define MVM_SOCKET_TYPE_RDM       4
#define MVM_SOCKET_TYPE_SEQPACKET 5

#define MVM_PROTOCOL_TYPE_ANY 0
#define MVM_PROTOCOL_TYPE_TCP 1
#define MVM_PROTOCOL_TYPE_UDP 2

#define MVM_DNS_FLAG_ADDRCONFIG 1
#define MVM_DNS_FLAG_PASSIVE    2

MVMObject * MVM_io_dns_lookup(MVMThreadContext *tc, MVMString *hostname,
        MVMint64 protocol_family, MVMint64 socket_type, MVMint64 protocol_type,
        MVMint64 packed);
