#include "moar.h"
#include "dasm_proto.h"
#include "platform/mmap.h"
#include "emit.h"

#define COPY_ARRAY(a, n, t) memcpy(MVM_malloc(n * sizeof(t)), a, n * sizeof(t))


static const MVMuint16 MAGIC_BYTECODE[] = { MVM_OP_sp_jit_enter, 0 };

MVMJitCode * MVM_jit_compile_graph(MVMThreadContext *tc, MVMJitGraph *jg) {
    dasm_State *state;
    char * memory;
    size_t codesize;
    /* Space for globals */
    MVMint32  num_globals = MVM_jit_num_globals();
    void ** dasm_globals = MVM_malloc(num_globals * sizeof(void*));
    MVMJitNode * node = jg->first_node;
    MVMJitCode * code;
    MVMint32 i;

    MVM_jit_log(tc, "Starting compilation\n");

    /* setup dasm (data and code section) */
    dasm_init(&state, 2);
    dasm_setupglobal(&state, dasm_globals, num_globals);
    dasm_setup(&state, MVM_jit_actions());
    dasm_growpc(&state, jg->labels_num);

    /* generate code */
    MVM_jit_emit_prologue(tc, jg,  &state);
    while (node) {
        switch(node->type) {
        case MVM_JIT_NODE_LABEL:
            MVM_jit_emit_label(tc, jg, &node->u.label, &state);
            break;
        case MVM_JIT_NODE_PRIMITIVE:
            MVM_jit_emit_primitive(tc, jg, &node->u.prim, &state);
            break;
        case MVM_JIT_NODE_BRANCH:
            MVM_jit_emit_branch(tc, jg, &node->u.branch, &state);
            break;
        case MVM_JIT_NODE_CALL_C:
            MVM_jit_emit_call_c(tc, jg, &node->u.call, &state);
            break;
        case MVM_JIT_NODE_GUARD:
            MVM_jit_emit_guard(tc, jg, &node->u.guard, &state);
            break;
        case MVM_JIT_NODE_INVOKE:
            MVM_jit_emit_invoke(tc, jg, &node->u.invoke, &state);
            break;
        case MVM_JIT_NODE_JUMPLIST:
            MVM_jit_emit_jumplist(tc, jg, &node->u.jumplist, &state);
            break;
        case MVM_JIT_NODE_CONTROL:
            MVM_jit_emit_control(tc, jg, &node->u.control, &state);
            break;
        case MVM_JIT_NODE_DATA:
            MVM_jit_emit_data(tc, jg, &node->u.data, &state);
            break;
        }
        node = node->next;
    }
    MVM_jit_emit_epilogue(tc, jg, &state);

    /* compile the function */
    dasm_link(&state, &codesize);
    memory = MVM_platform_alloc_pages(codesize, MVM_PAGE_READ|MVM_PAGE_WRITE);
    dasm_encode(&state, memory);
    /* set memory readable + executable */
    if (!MVM_platform_set_page_mode(memory, codesize, MVM_PAGE_READ|MVM_PAGE_EXEC)) {
        MVM_jit_log(tc, "Setting jit page executable failed or was denied. deactivating jit.\n");

        dasm_free(&state);
        MVM_free(dasm_globals);
        tc->instance->jit_enabled = 0;
        return NULL;
    }


    MVM_jit_log(tc, "Bytecode size: %"MVM_PRSz"\n", codesize);
    /* Create code segment */
    code = MVM_malloc(sizeof(MVMJitCode));
    code->func_ptr   = (MVMJitFunc)memory;
    code->size       = codesize;
    code->bytecode   = (MVMuint8*)MAGIC_BYTECODE;
    code->sf         = jg->sg->sf;

    /* Get the basic block labels */
    code->num_labels = jg->labels_num;
    code->labels = MVM_malloc(sizeof(void*) * code->num_labels);
    for (i = 0; i < code->num_labels; i++) {
        MVMint32 offset = dasm_getpclabel(&state, i);
        if (offset < 0)
            MVM_jit_log(tc, "Got negative offset for dynamic label %d\n", i);
        code->labels[i] = memory + offset;
    }

    /* Copy the deopts, inlines, and handlers. Because these use the label index
     * rather than the direct pointer, no fixup is necessary */
    code->num_bbs      = jg->bbs_num;
    code->bb_labels    = COPY_ARRAY(jg->bbs, jg->bbs_num, MVMint32);

    code->num_deopts   = jg->deopts_num;
    code->deopts       = code->num_deopts ? COPY_ARRAY(jg->deopts, jg->deopts_num, MVMJitDeopt) : NULL;
    code->num_handlers = jg->handlers_num;
    code->handlers     = code->num_handlers ? COPY_ARRAY(jg->handlers, jg->handlers_alloc, MVMJitHandler) : NULL;
    code->num_inlines  = jg->inlines_num;
    code->inlines      = code->num_inlines ? COPY_ARRAY(jg->inlines, jg->inlines_alloc, MVMJitInline) : NULL;

    /* clear up the assembler */
    dasm_free(&state);
    MVM_free(dasm_globals);

    code->seq_nr = MVM_incr(&tc->instance->jit_seq_nr);

    if (tc->instance->jit_bytecode_dir) {
        MVM_jit_log_bytecode(tc, code);
    }
    if (tc->instance->jit_log_fh)
        fflush(tc->instance->jit_log_fh);
    return code;
}

void MVM_jit_destroy_code(MVMThreadContext *tc, MVMJitCode *code) {
    MVM_platform_free_pages(code->func_ptr, code->size);
    MVM_free(code->bb_labels);
    MVM_free(code->deopts);
    MVM_free(code->handlers);
    MVM_free(code->inlines);
    MVM_free(code);
}

/* Enter the JIT code segment. The label is a continuation point where control
 * is resumed after the frame is properly setup. */
void MVM_jit_enter_code(MVMThreadContext *tc, MVMCompUnit *cu,
                        MVMJitCode *code) {
    void *label = tc->cur_frame->jit_entry_label;
    if (label < (void*)code->func_ptr || (char*)label > (((char*)code->func_ptr) + code->size))
        MVM_oops(tc, "JIT entry label out of range for code!\n"
                 "(label %p, func_ptr %p, code size %lui, offset %li, frame_nr %i, seq nr %i)",
                 label, code->func_ptr, code->size, ((char*)label) - ((char*)code->func_ptr),
                 tc->cur_frame->sequence_nr, code->seq_nr);
    code->func_ptr(tc, cu, label);
}
