typedef void (*MVMIOGetUsableAddressCB)(
    MVMThreadContext  *tc,
    char              *host_cstr,
    int                port,
    unsigned short     family,
    struct addrinfo  **result,
    void              *misc_data
);

MVMObject * MVM_io_socket_create(MVMThreadContext *tc, MVMint64 listen);
void MVM_io_get_usable_address(
    MVMThreadContext         *tc,
    char                     *host_cstr,
    int                       port,
    unsigned short            family,
    struct addrinfo         **result,
    void                     *misc_data,
    MVMIOGetUsableAddressCB   cb
);
struct addrinfo * MVM_io_resolve_host_name(MVMThreadContext *tc, MVMString *host, MVMint64 port);
MVMString * MVM_io_get_hostname(MVMThreadContext *tc);
