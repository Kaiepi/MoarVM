MVMObject * MVM_io_socket_create(MVMThreadContext *tc,
        MVMint64 family, MVMint64 type, MVMint64 protocol,
        MVMint64 passive);

MVMString * MVM_io_get_hostname(MVMThreadContext *tc);
