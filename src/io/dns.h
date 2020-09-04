MVMObject * MVM_io_dns_resolve(MVMThreadContext *tc,
        MVMString *hostname, MVMuint16 port,
        MVMint64 family_value, MVMint64 type_value, MVMint64 protocol_value,
        MVMint64 passive);

MVMObject * MVM_io_dns_create_resolver(MVMThreadContext *tc,
        MVMArray *name_servers, MVMuint16 default_port,
        MVMObject *buf_type);

MVMObject * MVM_io_dns_query_async(MVMThreadContext *tc,
        MVMResolver *resolver, MVMObject *queue, MVMObject *schedulee,
        MVMString *domain_name, MVMint64 type, MVMint64 class,
        MVMObject *async_task);
