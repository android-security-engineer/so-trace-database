package io.sotrace.unidbg;

import io.sotrace.unidbg.model.*;
import io.sotrace.unidbg.transport.EventBatcher;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EventBatcherTest {

    @Test
    void drain_returns_all_events_and_resets() {
        EventBatcher batcher = new EventBatcher();

        long seq = batcher.nextSeq();
        batcher.ensureThread(1, 0);
        batcher.addInstruction(new InstructionEvent(seq, 1, 0x1000L, false, false));
        batcher.addMemoryWrite(new MemoryWriteEvent(seq, 1, 0x2000L, new byte[]{0x1, 0x2}));
        batcher.addMemoryRead(new MemoryReadEvent(seq, 1, 0x2000L, 2));
        batcher.addSync(new SyncEvent(seq, 1, "MutexLock", 0x3000L, "Success"));

        assertFalse(batcher.isEmpty());

        TraceEnvelope envelope = batcher.drain(42L);

        assertEquals(42L, envelope.traceId);
        assertEquals(1, envelope.threads.size());
        assertEquals(1, envelope.instructions.size());
        assertEquals(1, envelope.memoryWrites.size());
        assertEquals(1, envelope.memoryReads.size());
        assertEquals(1, envelope.syncEvents.size());

        // After drain the batcher must be empty
        assertTrue(batcher.isEmpty());
    }

    @Test
    void ensureThread_deduplicates() {
        EventBatcher batcher = new EventBatcher();
        batcher.ensureThread(1, 0);
        batcher.ensureThread(1, 100); // same tid — must not add a second entry
        batcher.ensureThread(2, 50);  // different tid — must add

        TraceEnvelope envelope = batcher.drain(1L);
        assertEquals(2, envelope.threads.size());
    }

    @Test
    void seq_is_monotonically_increasing() {
        EventBatcher batcher = new EventBatcher();
        long s1 = batcher.nextSeq();
        long s2 = batcher.nextSeq();
        long s3 = batcher.nextSeq();
        assertTrue(s1 < s2);
        assertTrue(s2 < s3);
    }

    @Test
    void drain_with_no_events_returns_empty_envelope() {
        EventBatcher batcher = new EventBatcher();
        TraceEnvelope envelope = batcher.drain(99L);
        assertEquals(99L, envelope.traceId);
        assertTrue(envelope.instructions.isEmpty());
        assertTrue(envelope.threads.isEmpty());
        assertTrue(envelope.syncEvents.isEmpty());
    }
}
