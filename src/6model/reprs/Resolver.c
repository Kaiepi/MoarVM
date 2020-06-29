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
static AO_t call_dns_init = 1;
static void initialize(MVMThreadContext *tc, MVMSTable *st, MVMObject *root, void *data) {
    MVMResolverBody    *body;
    MVMResolverContext *context;

    body = (MVMResolverBody *)data;
    if (MVM_cas(&call_dns_init, 1, 0))
        dns_init(NULL, 0);
    for (context = body->contexts; context != body->contexts + MVM_RES_POOL_LEN; ++context) {
        context->ctx    = dns_new(NULL);
        context->handle = MVM_malloc(sizeof(uv_poll_t));
    }
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

    body = (MVMResolverBody *)data;
    if (MVM_cas(&call_dns_init, 1, 0))
        dns_init(NULL, 0);
    for (context = body->contexts; context != body->contexts + MVM_RES_POOL_LEN; ++context) {
        context->ctx    = dns_new(NULL);
        context->handle = MVM_malloc(sizeof(uv_poll_t));
    }
}

/* Sets the size of the STable. */
static void deserialize_stable_size(MVMThreadContext *tc, MVMSTable *st, MVMSerializationReader *reader) {
    st->size = sizeof(MVMResolver);
}

/* Called by the VM in order to free memory associated with this object. */
static void gc_free(MVMThreadContext *tc, MVMObject *obj) {
    MVMResolver        *resolver;
    MVMResolverContext *context;

    resolver = (MVMResolver *)resolver;
    for (context = resolver->body.contexts; context != resolver->body.contexts + MVM_RES_POOL_LEN; ++context) {
        dns_free(context->ctx);
        MVM_free(context->handle);
    }
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
