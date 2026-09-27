package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Thread registration metadata — emitted once per thread on first sight. */
public class ThreadEvent {

    @JsonProperty("thread_id")
    public final int threadId;

    @JsonProperty("create_step")
    public final long createStep;

    @JsonProperty("parent_thread_id")
    public final int parentThreadId;

    @JsonProperty("stack_base")
    public final long stackBase;

    @JsonProperty("stack_size")
    public final long stackSize;

    @JsonProperty("tls_addr")
    public final long tlsAddr;

    @JsonProperty("is_jni_attached")
    public final boolean isJniAttached;

    public ThreadEvent(int threadId, long createStep) {
        this.threadId       = threadId;
        this.createStep     = createStep;
        this.parentThreadId = 0;
        this.stackBase      = 0;
        this.stackSize      = 0;
        this.tlsAddr        = 0;
        this.isJniAttached  = false;
    }
}
