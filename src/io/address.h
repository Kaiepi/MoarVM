MVMuint16 MVM_address_port(MVMThreadContext *tc, MVMAddress *address);
MVMuint32 MVM_address_flowinfo(MVMThreadContext *tc, MVMAddress *address);
MVMuint32 MVM_address_scope_id(MVMThreadContext *tc, MVMAddress *address);

MVMint64 MVM_address_family(MVMThreadContext *tc, MVMAddress *address);
MVMint64 MVM_address_type(MVMThreadContext *tc, MVMAddress *address);
MVMint64 MVM_address_protocol(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_from_ipv4_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port,
        MVMint64 type, MVMint64 protocol);
MVMObject * MVM_address_from_ipv6_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port, MVMuint32 flowinfo, MVMuint32 scope_id,
        MVMint64 type, MVMint64 protocol);
MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path, MVMint64 type, MVMint64 protocol);
MVMString * MVM_address_to_presentation(MVMThreadContext *tc, MVMAddress *address);

MVMObject * MVM_address_resolve_sync(MVMThreadContext *tc,
        MVMString *host, MVMuint16 port,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive);
