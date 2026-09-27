# SoTrace Pintool — Intel Pin instrumentation for sotrace-database
#
# Usage:
#   PIN_ROOT=/opt/pin make
#   PIN_ROOT=/opt/pin make clean
#
# The resulting libsotrace_pintool.so is then used as:
#   $PIN_ROOT/pin -t libsotrace_pintool.so -so libfoo.so -o /tmp/trace.jsonl -- ./binary

PIN_ROOT ?= /opt/pin

TARGET := libsotrace_pintool.so

CXX      := g++
CXXFLAGS := -std=c++14 -Wall -Wno-unknown-pragmas -fno-stack-protector \
            -DTARGET_LINUX -DHOST_IA32E -DTARGET_IA32E \
            -I$(PIN_ROOT)/source/include/pin \
            -I$(PIN_ROOT)/source/include/pin/gen \
            -I$(PIN_ROOT)/extras/components/include \
            -I$(PIN_ROOT)/extras/xed-intel64/include/xed \
            -I$(PIN_ROOT)/source/tools/InstLib \
            -fPIC -O2

LDFLAGS  := -shared -Wl,--hash-style=sysv \
            -L$(PIN_ROOT)/intel64/runtime/pincrt \
            -L$(PIN_ROOT)/intel64/lib \
            -L$(PIN_ROOT)/intel64/lib-ext \
            -L$(PIN_ROOT)/extras/xed-intel64/lib \
            -lpin -lxed -lpindwarf -ldl -lpthread -lm -lc

.PHONY: all clean

all: $(TARGET)

$(TARGET): SoTracePintool.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
