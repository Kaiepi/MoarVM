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
    MVMResolverBody *body;
    size_t           i;

    body = (MVMResolverBody *)data;
    for (i = 0; i < MVM_RESOLVER_CONTEXTS; ++i) {
        MVMResolverContext *context;
        int                 error;

        context = &body->contexts[i];
        if ((error = ares_init(&context->channel)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS context: %s",
                ares_strerror(error));

        context->rwlock_query_info = MVM_malloc(sizeof(uv_rwlock_t));
        if ((error = uv_rwlock_init(context->rwlock_query_info)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS context: %s",
                ares_strerror(error));
    }
    body->sem_contexts = MVM_malloc(sizeof(uv_sem_t));
    uv_sem_init(body->sem_contexts, MVM_RESOLVER_CONTEXTS);
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
    MVMResolverBody *body;
    size_t           i;

    body = (MVMResolverBody *)data;
    for (i = 0; i < MVM_RESOLVER_CONTEXTS; ++i) {
        MVMResolverContext *context;
        int                 error;

        context = &body->contexts[i];
        if ((error = ares_init(&context->channel)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS context: %s",
                ares_strerror(error));

        context->rwlock_query_info = MVM_malloc(sizeof(uv_rwlock_t));
        if ((error = uv_rwlock_init(context->rwlock_query_info)))
            MVM_exception_throw_adhoc(tc,
                "Failed to initialize a DNS context: %s",
                ares_strerror(error));
    }
    body->sem_contexts = MVM_malloc(sizeof(uv_sem_t));
    uv_sem_init(body->sem_contexts, MVM_RESOLVER_CONTEXTS);
}

/* Sets the size of the STable. */
static void deserialize_stable_size(MVMThreadContext *tc, MVMSTable *st, MVMSerializationReader *reader) {
    st->size = sizeof(MVMResolver);
}

/* Called by the VM in order to free memory associated with this object. */
static void gc_free(MVMThreadContext *tc, MVMObject *obj) {
    MVMResolver *resolver;
    size_t       i;

    resolver = (MVMResolver *)obj;
    for (i = 0; i < MVM_RESOLVER_CONTEXTS; ++i) {
        MVMResolverContext *context = &resolver->body.contexts[i];
        ares_cancel(context->channel);
        ares_destroy(context->channel);
        uv_rwlock_destroy(context->rwlock_query_info);
    }
    uv_sem_destroy(resolver->body.sem_contexts);
}

/* Composes the representation. */
static void compose(MVMThreadContext *tc, MVMSTable *st, MVMObject *info) {
    /* Nothing doing. */
}

/* Calculates the non-GC-managed memory we hold on to. */
static MVMuint64 unmanaged_size(MVMThreadContext *tc, MVMSTable *st, void *data) {
    return MVM_RESOLVER_CONTEXTS * (sizeof(MVMResolverQueryInfo) + sizeof(uv_rwlock_t)) + sizeof(uv_sem_t);
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
    unmanaged_size,
    NULL, /* describe_refs */
};
