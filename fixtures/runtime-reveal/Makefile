CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BUILD := build

.PHONY: all check clean

all: $(BUILD)/libreveal.so $(BUILD)/reveal-run

$(BUILD)/libreveal.so: src/reveal.c
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

$(BUILD)/reveal-run: src/reveal_run.c
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< -ldl

check: all
	./scripts/check.sh

clean:
	rm -rf $(BUILD)
