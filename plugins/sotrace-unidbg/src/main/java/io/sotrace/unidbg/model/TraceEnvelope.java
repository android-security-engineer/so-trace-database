package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * JSON envelope posted to {@code POST /api/v1/traces/import}.
 *
 * Field names match sotrace-server's {@code TraceImportRequest} struct exactly.
 */
public class TraceEnvelope {

    @JsonProperty("trace_id")
    public final long traceId;

    public final List<ThreadEvent> threads;

    public final List<InstructionEvent> instructions;

    @JsonProperty("memory_writes")
    public final List<MemoryWriteEvent> memoryWrites;

    @JsonProperty("memory_reads")
    public final List<MemoryReadEvent> memoryReads;

    @JsonProperty("sync_events")
    public final List<SyncEvent> syncEvents;

    @JsonProperty("context_switches")
    public final List<Object> contextSwitches;

    @JsonProperty("state_changes")
    public final List<Object> stateChanges;

    @JsonProperty("jni_calls")
    public final List<Object> jniCalls;

    public final List<CallEvent> calls;

    public TraceEnvelope(
            long traceId,
            List<ThreadEvent> threads,
            List<InstructionEvent> instructions,
            List<MemoryWriteEvent> memoryWrites,
            List<MemoryReadEvent> memoryReads,
            List<SyncEvent> syncEvents,
            List<CallEvent> calls) {
        this.traceId        = traceId;
        this.threads        = threads;
        this.instructions   = instructions;
        this.memoryWrites   = memoryWrites;
        this.memoryReads    = memoryReads;
        this.syncEvents     = syncEvents;
        this.contextSwitches = List.of();
        this.stateChanges   = List.of();
        this.jniCalls       = List.of();
        this.calls          = calls;
    }
}
