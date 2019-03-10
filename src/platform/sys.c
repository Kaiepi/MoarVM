#include "moar.h"
#include "platform/sys.h"

MVMuint32 MVM_platform_cpu_count(void) {
    int count;
    uv_cpu_info_t *info;
    int e;

    e = uv_cpu_info(&info, &count);
    if (e == 0) uv_free_cpu_info(info, count);

    return count;
}

MVMuint64 MVM_platform_free_memory(void) {
    return uv_get_free_memory();
}

MVMuint64 MVM_platform_total_memory(void) {
    return uv_get_total_memory();
}
