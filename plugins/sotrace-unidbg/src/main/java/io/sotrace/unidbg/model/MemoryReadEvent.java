package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A memory read captured from unidbg TraceReadListener.
 * Reads are forwarded to sotrace's race detector but not persisted as memory state.
 */
public class MemoryReadEvent {

    public final long step;

    @JsonProperty("thread_id")
    public final int threadId;

    public final long address;

    public final int size;

    public MemoryReadEvent(long step, int threadId, long address, int size) {
        this.step     = step;
        this.threadId = threadId;
        this.address  = address;
        this.size     = size;
    }
}
