MVMObject * MVM_address_from_ipv4_presentation(MVMThreadContext *tc, MVMString *presentation, MVMuint16 port);
MVMObject * MVM_address_from_ipv6_presentation(MVMThreadContext *tc,
        MVMString *presentation, MVMuint16 port, MVMString *zone_id);
MVMObject * MVM_address_from_path(MVMThreadContext *tc, MVMString *path);

MVMObject * MVM_address_from_ipv4_address(MVMThreadContext *tc, MVMArray *buf, MVMuint16 port);
MVMObject * MVM_address_from_ipv6_address(MVMThreadContext *tc, MVMArray *buf, MVMuint16 port, MVMString *zone_id);
MVMObject * MVM_address_from_unix_address(MVMThreadContext *tc, MVMArray *buf);

MVMuint16 MVM_address_get_port(MVMThreadContext *tc, MVMAddress *address);
MVMuint32 MVM_address_get_scope_id(MVMThreadContext *tc, MVMAddress *address);

MVMString * MVM_address_to_string(MVMThreadContext *tc, MVMAddress *address);
MVMObject * MVM_address_to_buffer(MVMThreadContext *tc, MVMAddress *address, MVMArray *buf_type);
