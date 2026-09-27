package io.sotrace.unidbg.collector;

import com.github.unidbg.Emulator;
import com.github.unidbg.memory.MemoryReadListener;
import com.github.unidbg.memory.MemoryWriteListener;
import io.sotrace.unidbg.SoTraceConfig;
import io.sotrace.unidbg.model.MemoryReadEvent;
import io.sotrace.unidbg.model.MemoryWriteEvent;
import io.sotrace.unidbg.transport.EventBatcher;

/**
 * Captures memory reads and writes.
 *
 * Register with:
 * <pre>{@code
 * emulator.traceRead(0, Long.MAX_VALUE, memoryCollector);
 * emulator.traceWrite(0, Long.MAX_VALUE, memoryCollector);
 * }</pre>
 *
 * Note: MemoryReadListener and MemoryWriteListener live in
 * {@code com.github.unidbg.memory} in unidbg 0.9.x.
 */
public class MemoryCollector implements MemoryWriteListener, MemoryReadListener {

    private final SoTraceConfig config;
    private final EventBatcher  batcher;

    public MemoryCollector(SoTraceConfig config, EventBatcher batcher) {
        this.config  = config;
        this.batcher = batcher;
    }

    // -------------------------------------------------------------------------
    // MemoryWriteListener
    // -------------------------------------------------------------------------

    @Override
    public void onWrite(Emulator<?> emulator, long address, int size, long value) {
        long seq  = batcher.nextSeq();
        int  tid  = 1; // memory listeners don't expose tid directly
        long addr = toSoOffset(address);

        // Convert value to little-endian bytes of the given size
        byte[] data = toLittleEndian(value, size);

        batcher.addMemoryWrite(new MemoryWriteEvent(seq, tid, addr, data));
    }

    // -------------------------------------------------------------------------
    // MemoryReadListener
    // -------------------------------------------------------------------------

    @Override
    public void onRead(Emulator<?> emulator, long address, byte[] value, int operandSize) {
        long seq  = batcher.nextSeq();
        int  tid  = 1;
        long addr = toSoOffset(address);
        int  sz   = operandSize > 0 ? operandSize : (value != null ? value.length : 1);

        batcher.addMemoryRead(new MemoryReadEvent(seq, tid, addr, sz));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private long toSoOffset(long address) {
        if (config.soBase == 0) return address;
        long offset = address - config.soBase;
        return offset >= 0 ? offset : address;
    }

    private static byte[] toLittleEndian(long value, int size) {
        int safeSize = Math.min(Math.max(size, 1), 8);
        byte[] result = new byte[safeSize];
        for (int i = 0; i < safeSize; i++) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }
}
