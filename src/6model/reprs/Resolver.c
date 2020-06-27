#include "moar.h"


/* This representation's function pointer table. */
static const MVMREPROps Resolver_this_repr;

/* Creates a new type object of this representation, and associates it with
 * the given HOW. */
static MVMObject * type_object_for(MVMThreadContext *tc, MVMObject *HOW) {
    MVMSTable *st = MVM_gc_allocate_stable(tc, &Resolver_this_repr, HOW);

    MVMROOT(tc, st,  {
        MVMObject *obj = MVM_gc_allocate_type_object(tc, st);
        MVM_ASSIGN_REF(tc, &(st->header), st->WHAT, obj);
        st->size = sizeof(MVMResolver);
    });

    return st->WHAT;
}

/* Initializes a new instance. */
static void initialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data) {
    MVMResolverBody    *body;
    MVMResolverContext *context;
    int                 error;

    /* ares_library_initialized returns an error code if the library hasn't been initialized yet, not 0! */
    if (ares_library_initialized()
     && (error = ares_library_init_mem(ARES_LIB_INIT_ALL, MVM_malloc, MVM_free, MVM_realloc)))
        MVM_exception_throw_adhoc(tc,
            "Failed to initialize a DNS resolution context: %s",
            ares_strerror(error));

    body = (MVMResolverBody *)data;
    for (context = body->contexts; context != body->contexts + MVM_RESOLVER_POOL_SIZE; ++context) {
        if ((error = ares_init(&context->channel)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS resolution context: %s",
                ares_strerror(error));
        if ((error = uv_sem_init(&context->sem_query, 1)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS resolution context: %s",
                uv_strerror(error));
    }
    if ((error = uv_sem_init(&body->sem_contexts, MVM_RESOLVER_POOL_SIZE)))
        MVM_exception_throw_adhoc(tc,
            "Failed to initialize a DNS resolution context: %s",
            uv_strerror(error));
}

/* Copies to the body of one object to another. */
static void copy_to(MVMThreadContext *tc, MVMSTable *st, void *src, MVMObject *dest_root, void *dest) {
    MVM_exception_throw_adhoc(tc, "Cannot copy object with representation Resolver");
}

static const MVMStorageSpec storage_spec = {
    MVM_STORAGE_SPEC_REFERENCE, /* inlineable */
    0,                          /* bits */
    0,                          /* align */
    MVM_STORAGE_SPEC_BP_NONE,   /* boxed_primitive */
    0,                          /* can_box */
    0,                          /* is_unsigned */
};

/* Gets the storage specification for this representation. */
static const MVMStorageSpec * get_storage_spec(MVMThreadContext *tc, MVMSTable *st) {
    return &storage_spec;
}

/* Serializes the data. */
static void serialize(MVMThreadContext *tc, MVMSTable *st, void *data, MVMSerializationWriter *writer) {
    /* Nothing doing. */
}

/* Deserializes the data. */
static void deserialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data, MVMSerializationReader *reader) {
    MVMResolverBody    *body;
    MVMResolverContext *context;
    int                 error;

    if (!ares_library_initialized()
     && (error = ares_library_init_mem(ARES_LIB_INIT_ALL, MVM_malloc, MVM_free, MVM_realloc)))
        MVM_exception_throw_adhoc(tc,
            "Failed to initialize a DNS resolution context: %s",
            ares_strerror(error));

    body = (MVMResolverBody *)data;
    for (context = body->contexts; context != body->contexts + MVM_RESOLVER_POOL_SIZE; ++context) {
        if ((error = ares_init(&context->channel)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS resolution context: %s",
                ares_strerror(error));
        if ((error = uv_sem_init(&context->sem_query, 1)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS resolution context: %s",
                uv_strerror(error));
    }
    if ((error = uv_sem_init(&body->sem_contexts, MVM_RESOLVER_POOL_SIZE)))
        MVM_exception_throw_adhoc(tc,
            "Failed to initialize a DNS resolution context: %s",
            uv_strerror(error));
}

/* Sets the size of the STable. */
static void deserialize_stable_size(MVMThreadContext *tc, MVMSTable *st, MVMSerializationReader *reader) {
    st->size = sizeof(MVMResolver);
}

/* Called by the VM in order to free memory associated with this object. */
static void gc_free(MVMThreadContext *tc, MVMObject *obj) {
    MVMResolver        *resolver;
    MVMResolverContext *context;

    resolver = (MVMResolver *)obj;
    for (context = resolver->body.contexts; context != resolver->body.contexts + MVM_RESOLVER_POOL_SIZE; ++context) {
        ares_destroy(context->channel);
        uv_sem_destroy(&context->sem_query);
    }
    uv_sem_destroy(&resolver->body.sem_contexts);

    /* XXX: Belongs elsewhere. */
    if (!ares_library_initialized())
        ares_library_cleanup();
}

/* Composes the representation. */
static void compose(MVMThreadContext *tc, MVMSTable *st, MVMObject *info) {
    /* Nothing doing. */
}

/* Initializes the representation. */
const MVMREPROps * MVMResolver_initialize(MVMThreadContext *tc) {
    return &Resolver_this_repr;
}

static const MVMREPROps Resolver_this_repr = {
    type_object_for,
    MVM_gc_allocate_object,
    initialize,
    copy_to,
    MVM_REPR_DEFAULT_ATTR_FUNCS,
    MVM_REPR_DEFAULT_BOX_FUNCS,
    MVM_REPR_DEFAULT_POS_FUNCS,
    MVM_REPR_DEFAULT_ASS_FUNCS,
    MVM_REPR_DEFAULT_ELEMS,
    get_storage_spec,
    NULL, /* change_type */
    serialize,
    deserialize,
    NULL, /* serialize_repr_data */
    NULL, /* deserialize_repr_data */
    deserialize_stable_size,
    NULL, /* gc_mark */
    gc_free,
    NULL, /* gc_cleanup */
    NULL, /* gc_mark_repr_data */
    NULL, /* gc_free_repr_data */
    compose,
    NULL, /* spesh */
    "Resolver", /* name */
    MVM_REPR_ID_MVMResolver,
    NULL, /* unmanaged_size */
    NULL, /* describe_refs */
};
