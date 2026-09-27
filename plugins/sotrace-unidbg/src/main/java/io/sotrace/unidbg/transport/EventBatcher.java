package io.sotrace.unidbg.transport;

import io.sotrace.unidbg.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe event buffer.
 *
 * All append operations are synchronized on separate per-list locks to allow
 * concurrent instruction/memory/sync collection from unidbg callbacks without
 * blocking each other.  {@link #drain(long)} is a stop-the-world snapshot:
 * it grabs all three locks, copies the data, clears the lists, and returns a
 * {@link TraceEnvelope} ready for HTTP upload.
 */
public class EventBatcher {

    private final AtomicLong seq = new AtomicLong(1);

    private final Object instrLock  = new Object();
    private final Object memLock    = new Object();
    private final Object syncLock   = new Object();
    private final Object callLock   = new Object();

    private List<ThreadEvent>      threads      = new ArrayList<>();
    private List<InstructionEvent> instructions = new ArrayList<>();
    private List<MemoryWriteEvent> memoryWrites = new ArrayList<>();
    private List<MemoryReadEvent>  memoryReads  = new ArrayList<>();
    private List<SyncEvent>        syncEvents   = new ArrayList<>();
    private List<CallEvent>        calls        = new ArrayList<>();

    /** Tracks which thread IDs have already had a ThreadEvent emitted. */
    private final Set<Integer> knownThreads = ConcurrentHashMap.newKeySet();

    // -------------------------------------------------------------------------
    // Sequence
    // -------------------------------------------------------------------------

    public long nextSeq() {
        return seq.getAndIncrement();
    }

    public long size() {
        synchronized (instrLock) { return instructions.size(); }
    }

    // -------------------------------------------------------------------------
    // Append
    // -------------------------------------------------------------------------

    /** Ensures a thread registration event exists for {@code tid}. */
    public void ensureThread(int tid, long createStep) {
        if (knownThreads.add(tid)) {
            synchronized (instrLock) {
                threads.add(new ThreadEvent(tid, createStep));
            }
        }
    }

    public void addInstruction(InstructionEvent event) {
        synchronized (instrLock) {
            instructions.add(event);
        }
    }

    public void addMemoryWrite(MemoryWriteEvent event) {
        synchronized (memLock) {
            memoryWrites.add(event);
        }
    }

    public void addMemoryRead(MemoryReadEvent event) {
        synchronized (memLock) {
            memoryReads.add(event);
        }
    }

    public void addSync(SyncEvent event) {
        synchronized (syncLock) {
            syncEvents.add(event);
        }
    }

    public void addCall(CallEvent event) {
        synchronized (callLock) {
            calls.add(event);
        }
    }

    // -------------------------------------------------------------------------
    // Drain
    // -------------------------------------------------------------------------

    /**
     * Atomically snapshot all buffered events into a {@link TraceEnvelope} and
     * reset the internal lists.  Safe to call from any thread.
     */
    public TraceEnvelope drain(long traceId) {
        List<ThreadEvent>      t;
        List<InstructionEvent> i;
        List<MemoryWriteEvent> mw;
        List<MemoryReadEvent>  mr;
        List<SyncEvent>        se;
        List<CallEvent>        c;

        synchronized (instrLock) {
            synchronized (memLock) {
                synchronized (syncLock) {
                    synchronized (callLock) {
                        t  = threads;      threads      = new ArrayList<>();
                        i  = instructions; instructions = new ArrayList<>();
                        mw = memoryWrites; memoryWrites = new ArrayList<>();
                        mr = memoryReads;  memoryReads  = new ArrayList<>();
                        se = syncEvents;   syncEvents   = new ArrayList<>();
                        c  = calls;        calls        = new ArrayList<>();
                        knownThreads.clear();
                    }
                }
            }
        }

        return new TraceEnvelope(traceId, t, i, mw, mr, se, c);
    }

    public boolean isEmpty() {
        synchronized (instrLock) {
            return instructions.isEmpty() && threads.isEmpty();
        }
    }
}
