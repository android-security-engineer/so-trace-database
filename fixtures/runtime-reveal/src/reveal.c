#include <stddef.h>
#include <stdint.h>

/* Mix caller-supplied bytes. The result is not a constant in this file:
 * the input lives in the process that calls this function. */
uint32_t sotrace_runtime_mix(const uint8_t *bytes, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    hash ^= hash >> 16;
    return hash;
}
