#include "trace_storm.h"

enum { EVENTS_PER_ROUND = 32 };

size_t sotrace_mock_events_per_round(void) {
    return EVENTS_PER_ROUND;
}

int sotrace_mock_run(uint64_t rounds, sotrace_mock_sink sink, void *context) {
    if (sink == NULL) {
        return -1;
    }

    /* Keep a little real computation so optimizers cannot collapse the loop. */
    uint32_t state = 0x9e3779b9u;
    for (uint64_t round = 0; round < rounds; ++round) {
        for (uint32_t slot = 0; slot < EVENTS_PER_ROUND; ++slot) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;

            uint32_t flags = 0;
            if (slot == 7 || slot == 15 || slot == 23 || slot == 31) {
                flags |= SOTRACE_MOCK_FLAG_BRANCH;
                if (((state ^ (uint32_t)round) & 1u) != 0) {
                    flags |= SOTRACE_MOCK_FLAG_BRANCH_TAKEN;
                }
            }

            /* Four stable 32-byte logical basic blocks, 4-byte aligned. */
            sink(0x1000u + slot * 4u, flags, context);
        }
    }
    return 0;
}
