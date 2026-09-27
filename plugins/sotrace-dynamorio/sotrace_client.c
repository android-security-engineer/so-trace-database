/*
 * sotrace_client.c — DynamoRIO client for sotrace-database
 *
 * Instruments a target binary and writes a JSONL trace to a file.
 * Each line is one JSON object (instruction / mem_read / mem_write).
 *
 * Build:
 *   cmake -DDynamoRIO_DIR=/opt/DynamoRIO/cmake -B build && cmake --build build
 *
 * Run:
 *   drrun -c build/libsotrace_client.so -outfile /tmp/trace.jsonl -so libfoo.so \
 *         -- ./target_binary
 *
 * Simplifications vs. production use:
 *  - seq counter is not atomic; safe for single-threaded targets only
 *  - emit_instruction() called via clean call from JIT code; fprintf inside
 *    a clean call is allowed but slow — for high-throughput tracing prefer
 *    a thread-local ring buffer flushed in the exit event
 *  - Memory hooks are opt-in (#define SOTRACE_ENABLE_MEMORY 1 in CMake)
 *  - branch_taken is always false (would need post-branch clean call to detect)
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ---- Global state ---- */

static FILE        *g_out        = NULL;
static uint64_t     g_seq        = 0;
static app_pc       g_so_base    = NULL;
static size_t       g_so_size    = 0;
static char         g_so_filter[256] = {0};
static bool         g_mem_enabled = false;

static void *g_mutex = NULL;  /* DR mutex for fprintf serialization */

/* ---- Helpers ---- */

static inline bool in_so(app_pc pc)
{
    if (g_so_base == NULL) return true;  /* no filter: trace everything */
    return (pc >= g_so_base && pc < g_so_base + g_so_size);
}

static inline uint64_t to_offset(app_pc pc)
{
    if (g_so_base == NULL) return (uint64_t)(uintptr_t)pc;
    return (uint64_t)(pc - g_so_base);
}

/* ---- Clean-call targets (called from JIT-ted code) ---- */

static void
sotrace_emit_instr(uint64_t offset, int is_branch)
{
    dr_mutex_lock(g_mutex);
    fprintf(g_out,
        "{\"type\":\"instruction\",\"seq\":%"PRIu64",\"thread_id\":1,"
        "\"address\":%"PRIu64",\"is_branch\":%s,\"branch_taken\":false}\n",
        g_seq++, offset,
        is_branch ? "true" : "false");
    dr_mutex_unlock(g_mutex);
}

static void
sotrace_emit_mem_read(uint64_t addr, uint32_t size)
{
    dr_mutex_lock(g_mutex);
    fprintf(g_out,
        "{\"type\":\"mem_read\",\"step\":%"PRIu64",\"thread_id\":1,"
        "\"address\":%"PRIu64",\"size\":%u}\n",
        g_seq++, addr, size);
    dr_mutex_unlock(g_mutex);
}

/* For mem_write we read the value after the store using a pre-store hook.
 * We capture the value from the src operand (concretized at clean-call time). */
static void
sotrace_emit_mem_write(uint64_t addr, uint64_t val, uint32_t size)
{
    if (size > 8) size = 8;
    dr_mutex_lock(g_mutex);
    fprintf(g_out,
        "{\"type\":\"mem_write\",\"step\":%"PRIu64",\"thread_id\":1,"
        "\"address\":%"PRIu64",\"data\":[",
        g_seq++, addr);
    for (uint32_t i = 0; i < size; i++) {
        if (i > 0) fputc(',', g_out);
        fprintf(g_out, "%u", (unsigned)((val >> (i * 8)) & 0xFF));
    }
    fputs("]}\n", g_out);
    dr_mutex_unlock(g_mutex);
}

/* ---- BB instrumentation events ---- */

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating, void **user_data)
{
    *user_data = NULL;
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
    app_pc pc = instr_get_app_pc(instr);
    if (pc == NULL || !in_so(pc))
        return DR_EMIT_DEFAULT;

    uint64_t offset   = to_offset(pc);
    bool     is_branch = instr_is_cti(instr);

    /* Insert clean call BEFORE the instruction */
    dr_insert_clean_call(drcontext, bb, instr,
        (void *)sotrace_emit_instr,
        false /* don't save fp state */,
        2,
        OPND_CREATE_INT64((int64_t)offset),
        OPND_CREATE_INT32(is_branch ? 1 : 0));

#ifdef SOTRACE_ENABLE_MEMORY
    if (g_mem_enabled && instr_reads_memory(instr)) {
        /* Insert mem-read clean call.
         * drutil_insert_get_mem_addr fills a scratch reg with the address. */
        opnd_t mem_ref = instr_get_src(instr, 0);
        if (opnd_is_memory_reference(mem_ref)) {
            reg_id_t reg_addr, reg_tmp;
            drreg_reserve_register(drcontext, bb, instr, NULL, &reg_addr);
            drreg_reserve_register(drcontext, bb, instr, NULL, &reg_tmp);
            drutil_insert_get_mem_addr(drcontext, bb, instr, mem_ref,
                                       reg_addr, reg_tmp);
            uint32_t size = (uint32_t)opnd_size_in_bytes(opnd_get_size(mem_ref));
            dr_insert_clean_call(drcontext, bb, instr,
                (void *)sotrace_emit_mem_read, false, 2,
                opnd_create_reg(reg_addr),
                OPND_CREATE_INT32(size));
            drreg_unreserve_register(drcontext, bb, instr, reg_addr);
            drreg_unreserve_register(drcontext, bb, instr, reg_tmp);
        }
    }
#endif /* SOTRACE_ENABLE_MEMORY */

    return DR_EMIT_DEFAULT;
}

/* ---- Module load: locate the target SO ---- */

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    if (g_so_filter[0] == '\0') return;
    const char *name = dr_module_preferred_name(info);
    if (name == NULL) return;
    if (strstr(name, g_so_filter) != NULL) {
        g_so_base = info->start;
        g_so_size = (size_t)(info->end - info->start);
        dr_fprintf(STDERR,
            "[sotrace] Module matched: %s  base=%p  size=%zu\n",
            name, (void *)g_so_base, g_so_size);
    }
}

/* ---- Exit event ---- */

static void
event_exit(void)
{
    if (g_out && g_out != stderr) {
        fflush(g_out);
        fclose(g_out);
        g_out = NULL;
    }
    dr_mutex_destroy(g_mutex);
    drmgr_exit();
#ifdef SOTRACE_ENABLE_MEMORY
    drreg_exit();
#endif
}

/* ---- Client entry point ---- */

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    const char *outpath = "/tmp/sotrace-dynamorio.jsonl";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-outfile") == 0 && i + 1 < argc)
            outpath = argv[++i];
        else if (strcmp(argv[i], "-so") == 0 && i + 1 < argc)
            strncpy(g_so_filter, argv[++i], sizeof(g_so_filter) - 1);
        else if (strcmp(argv[i], "-mem") == 0)
            g_mem_enabled = true;
    }

    g_out = fopen(outpath, "w");
    if (!g_out) {
        dr_fprintf(STDERR, "[sotrace] Cannot open output: %s — using stderr\n", outpath);
        g_out = stderr;
    }

    g_mutex = dr_mutex_create();

    drmgr_init();

#ifdef SOTRACE_ENABLE_MEMORY
    if (g_mem_enabled) {
        drreg_options_t ops = {sizeof(ops), 3 /* max regs */, false};
        drreg_init(&ops);
        drutil_init();
    }
#endif

    drmgr_register_bb_instrumentation_event(
        event_bb_analysis, event_bb_insert, NULL);
    drmgr_register_module_load_event(event_module_load);
    dr_register_exit_event(event_exit);

    dr_fprintf(STDERR,
        "[sotrace] Client loaded  outfile=%s  so_filter=%s  mem=%s\n",
        outpath,
        g_so_filter[0] ? g_so_filter : "(none — trace all)",
        g_mem_enabled ? "on" : "off");
}
