package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/** A function call or return event for call-stack reconstruction. */
public class CallEvent {

    public final long seq;

    @JsonProperty("thread_id")
    public final int threadId;

    /**
     * Event type: "Call" or "Return".
     * Matches sotrace CallEventType enum.
     */
    @JsonProperty("event_type")
    public final String eventType;

    /** Caller address (SO-relative). */
    public final long caller;

    /** Callee address (SO-relative). */
    public final long callee;

    /** Call stack depth at the time of this event. */
    public final int depth;

    public CallEvent(long seq, int threadId, String eventType, long caller, long callee, int depth) {
        this.seq       = seq;
        this.threadId  = threadId;
        this.eventType = eventType;
        this.caller    = caller;
        this.callee    = callee;
        this.depth     = depth;
    }
}
