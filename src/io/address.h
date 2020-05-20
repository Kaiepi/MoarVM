MVMint64 MVM_address_family(MVMThreadContext *tc, MVMAddress *address);
MVMint64 MVM_address_type(MVMThreadContext *tc, MVMAddress *address);
MVMint64 MVM_address_protocol(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_resolve_sync(MVMThreadContext *tc,
        MVMString *host, MVMint64 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive);
