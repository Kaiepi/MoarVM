MVMObject * MVM_io_dns_resolve(MVMThreadContext *tc,
        MVMString *hostname, MVMuint16 port,
        MVMint64 family_value, MVMint64 type_value, MVMint64 protocol_value,
        MVMint64 passive);
