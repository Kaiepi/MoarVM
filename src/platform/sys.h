/*
 * Tries to determine the number of logical CPUs available to the process.
 * May return 0 on error.
 */
MVMuint32 MVM_platform_cpu_count(void);

/*
 * Gets the total free memory on the system.
 */
MVMuint64 MVM_platform_free_memory(void);

/*
 * Gets the total physical memory on the system.
 */
MVMuint64 MVM_platform_total_memory(void);
