MVMObject * MVM_io_socket_connect_async(MVMThreadContext *tc,
    MVMObject *address,
    MVMObject *queue, MVMObject *schedulee, MVMObject *async_type);
MVMObject * MVM_io_socket_listen_async(MVMThreadContext *tc,
    MVMObject *address, MVMint32 backlog,
    MVMObject *queue, MVMObject *schedulee, MVMObject *async_type);
