MVMObject * MVM_io_socket_connect_async(MVMThreadContext *tc, MVMObject *queue,
    MVMObject *schedulee, MVMObject *address, MVMObject *async_type);
MVMObject * MVM_io_socket_listen_async(MVMThreadContext *tc, MVMObject *queue,
    MVMObject *schedulee, MVMObject *address, MVMint32 backlog, MVMObject *async_type);
