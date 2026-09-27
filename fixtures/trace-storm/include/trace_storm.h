#ifndef SOTRACE_TRACE_STORM_H
#define SOTRACE_TRACE_STORM_H

#include <stddef.h>
#include <stdint.h>

/* Bit flags emitted alongside each deterministic logical instruction. */
#define SOTRACE_MOCK_FLAG_BRANCH 0x01u
#define SOTRACE_MOCK_FLAG_BRANCH_TAKEN 0x02u

typedef void (*sotrace_mock_sink)(uint32_t offset, uint32_t flags, void *context);

/* The fixed number of logical instructions emitted for every round. */
size_t sotrace_mock_events_per_round(void);

/*
 * Execute a deterministic workload and report each logical instruction through
 * sink. Offsets are stable SO-relative mock program counters. Returns zero on
 * success and -1 when sink is NULL.
 */
int sotrace_mock_run(uint64_t rounds, sotrace_mock_sink sink, void *context);

#endif
