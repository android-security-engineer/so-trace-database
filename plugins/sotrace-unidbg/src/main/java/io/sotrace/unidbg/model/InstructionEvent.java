package io.sotrace.unidbg.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A single executed instruction. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InstructionEvent {

    public final long seq;

    @JsonProperty("thread_id")
    public final int threadId;

    /** SO-relative address (raw address minus soBase). */
    public final long address;

    @JsonProperty("is_branch")
    public final boolean isBranch;

    @JsonProperty("branch_taken")
    public final boolean branchTaken;

    public InstructionEvent(long seq, int threadId, long address, boolean isBranch, boolean branchTaken) {
        this.seq         = seq;
        this.threadId    = threadId;
        this.address     = address;
        this.isBranch    = isBranch;
        this.branchTaken = branchTaken;
    }
}
