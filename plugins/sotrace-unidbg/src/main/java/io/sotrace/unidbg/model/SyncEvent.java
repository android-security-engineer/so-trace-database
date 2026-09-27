package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A synchronization event (mutex lock/unlock, condvar, futex, ...). */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SyncEvent {

    public final long step;

    @JsonProperty("thread_id")
    public final int threadId;

    /**
     * Sync type string matching sotrace SyncEventType enum:
     * "MutexLock", "MutexUnlock", "MutexTryLock", "FutexWait", "FutexWake",
     * "CondvarWait", "CondvarSignal", "CondvarBroadcast", etc.
     */
    @JsonProperty("sync_type")
    public final String syncType;

    @JsonProperty("sync_object_addr")
    public final long syncObjectAddr;

    /** "Success" or "Error" */
    public final String result;

    @JsonProperty("wait_duration_ns")
    public final Long waitDurationNs;

    public SyncEvent(long step, int threadId, String syncType, long syncObjectAddr, String result) {
        this(step, threadId, syncType, syncObjectAddr, result, null);
    }

    public SyncEvent(long step, int threadId, String syncType, long syncObjectAddr, String result, Long waitDurationNs) {
        this.step           = step;
        this.threadId       = threadId;
        this.syncType       = syncType;
        this.syncObjectAddr = syncObjectAddr;
        this.result         = result;
        this.waitDurationNs = waitDurationNs;
    }
}
