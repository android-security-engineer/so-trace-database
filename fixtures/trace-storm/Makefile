CC ?= cc
CFLAGS ?= -O3 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -fPIC -Iinclude
LDFLAGS ?=

BUILD_DIR := build
LIBRARY := $(BUILD_DIR)/libtrace_storm.so
CAPTURE := $(BUILD_DIR)/mock-trace-capture

.PHONY: all verify bench clean

all: $(LIBRARY) $(CAPTURE)

# End-to-end smoke test: generate a deterministic trace, persist it, then
# replay indexed address and thread queries against the stored trace.
verify: all
	sh scripts/verify.sh $(ROUNDS)

# Performance run: generate, persist, replay, and query a larger deterministic
# trace. The default is one million instruction records (31,250 rounds).
bench: all
	sh scripts/bench.sh $(ROUNDS)

$(BUILD_DIR):
	mkdir -p $@

$(LIBRARY): src/trace_storm.c include/trace_storm.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ src/trace_storm.c $(LDFLAGS)

$(CAPTURE): src/capture_trace.c include/trace_storm.h $(LIBRARY) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ src/capture_trace.c -L$(BUILD_DIR) -ltrace_storm -Wl,-rpath,'$$ORIGIN' $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
