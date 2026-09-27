package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** A memory write captured from unidbg TraceWriteListener. */
public class MemoryWriteEvent {

    public final long step;

    @JsonProperty("thread_id")
    public final int threadId;

    public final long address;

    /** Raw bytes written (little-endian). */
    public final byte[] data;

    public MemoryWriteEvent(long step, int threadId, long address, byte[] data) {
        this.step     = step;
        this.threadId = threadId;
        this.address  = address;
        this.data     = data;
    }
}
