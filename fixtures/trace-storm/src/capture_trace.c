#include "trace_storm.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum output_format {
    FORMAT_FRIDA,
    FORMAT_UNIDBG,
};

struct capture_context {
    FILE *output;
    uint64_t sequence;
    uint64_t events;
    uint32_t thread_id;
    uint32_t thread_count;
    enum output_format format;
    int failed;
};

/* Frida Stalker-shaped instruction event: `pc` field, `type: "inst"`. */
static int write_event_frida(struct capture_context *ctx, uint32_t offset, uint32_t flags) {
    return fprintf(
        ctx->output,
        "{\"type\":\"inst\",\"seq\":%" PRIu64
        ",\"tid\":%" PRIu32
        ",\"pc\":\"0x%" PRIx32
        "\",\"timestamp\":%" PRIu64
        ",\"is_branch\":%s,\"branch_taken\":%s}\n",
        ctx->sequence,
        ctx->thread_id,
        offset,
        ctx->sequence,
        (flags & SOTRACE_MOCK_FLAG_BRANCH) != 0 ? "true" : "false",
        (flags & SOTRACE_MOCK_FLAG_BRANCH_TAKEN) != 0 ? "true" : "false");
}

/* Unidbg callback-shaped instruction event: `address` field, `type: "instruction"`. */
static int write_event_unidbg(struct capture_context *ctx, uint32_t offset, uint32_t flags) {
    return fprintf(
        ctx->output,
        "{\"type\":\"instruction\",\"seq\":%" PRIu64
        ",\"tid\":%" PRIu32
        ",\"address\":\"0x%" PRIx32
        "\",\"is_branch\":%s,\"branch_taken\":%s}\n",
        ctx->sequence,
        ctx->thread_id,
        offset,
        (flags & SOTRACE_MOCK_FLAG_BRANCH) != 0 ? "true" : "false",
        (flags & SOTRACE_MOCK_FLAG_BRANCH_TAKEN) != 0 ? "true" : "false");
}

static void write_event(uint32_t offset, uint32_t flags, void *opaque) {
    struct capture_context *ctx = opaque;
    if (ctx->failed) {
        return;
    }

    int written = ctx->format == FORMAT_UNIDBG
        ? write_event_unidbg(ctx, offset, flags)
        : write_event_frida(ctx, offset, flags);
    if (written < 0) {
        ctx->failed = 1;
        return;
    }

    ctx->sequence += 1;
    ctx->events += 1;
    if ((ctx->events % sotrace_mock_events_per_round()) == 0) {
        /* Rotate threads between rounds to exercise the thread index. */
        uint64_t round_index = ctx->events / sotrace_mock_events_per_round();
        ctx->thread_id = 1000u + (uint32_t)(round_index % ctx->thread_count);
    }
}

static int parse_rounds(const char *input, uint64_t *rounds) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(input, &end, 10);
    if (errno != 0 || input == end || *end != '\0') {
        return -1;
    }
    *rounds = (uint64_t)value;
    return 0;
}

static int parse_thread_count(const char *input, uint32_t *thread_count) {
    uint64_t value = 0;
    if (parse_rounds(input, &value) != 0 || value == 0 ||
        value > (uint64_t)UINT32_MAX - 999u) {
        return -1;
    }
    *thread_count = (uint32_t)value;
    return 0;
}

static int parse_format(const char *input, enum output_format *format) {
    if (strcmp(input, "frida") == 0) {
        *format = FORMAT_FRIDA;
        return 0;
    }
    if (strcmp(input, "unidbg") == 0) {
        *format = FORMAT_UNIDBG;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: %s OUTPUT.jsonl ROUNDS [THREADS] [FORMAT: frida|unidbg]\n", argv[0]);
        return 2;
    }

    uint64_t rounds = 0;
    if (parse_rounds(argv[2], &rounds) != 0) {
        fprintf(stderr, "rounds must be a non-negative decimal integer: %s\n", argv[2]);
        return 2;
    }

    uint32_t thread_count = 2;
    if (argc >= 4 && parse_thread_count(argv[3], &thread_count) != 0) {
        fprintf(stderr, "threads must be a positive decimal integer: %s\n", argv[3]);
        return 2;
    }

    enum output_format format = FORMAT_FRIDA;
    if (argc == 5 && parse_format(argv[4], &format) != 0) {
        fprintf(stderr, "format must be one of: frida, unidbg (got %s)\n", argv[4]);
        return 2;
    }

    FILE *output = fopen(argv[1], "w");
    if (output == NULL) {
        perror(argv[1]);
        return 1;
    }
    if (setvbuf(output, NULL, _IOFBF, 1024 * 1024) != 0) {
        fprintf(stderr, "warning: could not enable a 1 MiB output buffer\n");
    }

    struct capture_context ctx = {
        .output = output,
        .sequence = 0,
        .events = 0,
        .thread_id = 1000,
        .thread_count = thread_count,
        .format = format,
        .failed = 0,
    };
    int result = sotrace_mock_run(rounds, write_event, &ctx);
    if (result != 0 || ctx.failed || fflush(output) != 0 || fclose(output) != 0) {
        fprintf(stderr, "failed while writing trace output\n");
        return 1;
    }

    fprintf(stderr, "wrote %" PRIu64 " instruction events (%" PRIu64
            " rounds, %" PRIu32 " threads, format=%s) to %s\n",
            ctx.events, rounds, thread_count,
            format == FORMAT_UNIDBG ? "unidbg" : "frida", argv[1]);
    return 0;
}
