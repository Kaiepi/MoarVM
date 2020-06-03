#define MVM_DNS_RECORD_TYPE_A    1
#define MVM_DNS_RECORD_TYPE_AAAA 28

#define MVM_DNS_RECORD_CLASS_IN 1

MVMObject * MVM_io_dns_resolve(MVMThreadContext *tc,
        MVMString *host, MVMuint16 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive);

MVMObject * MVM_io_dns_query_async(MVMThreadContext *tc,
        MVMObject *resolver, MVMString *question, MVMint64 type, MVMint64 class,
        MVMObject *queue, MVMObject *schedulee, MVMObject *async_type);
