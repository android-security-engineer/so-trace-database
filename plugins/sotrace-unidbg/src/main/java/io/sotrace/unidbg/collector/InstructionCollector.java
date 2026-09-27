package io.sotrace.unidbg.collector;

import com.github.unidbg.Emulator;
import com.github.unidbg.TraceCodeListener;
import com.github.unidbg.arm.backend.Backend;
import io.sotrace.unidbg.SoTraceConfig;
import io.sotrace.unidbg.model.InstructionEvent;
import io.sotrace.unidbg.transport.EventBatcher;
import unicorn.Instruction;

/**
 * Captures every executed instruction via unidbg's {@code TraceCodeListener}.
 *
 * Register with:
 * <pre>{@code
 * emulator.traceCode(begin, end, new InstructionCollector(config, batcher));
 * }</pre>
 */
public class InstructionCollector implements TraceCodeListener {

    private final SoTraceConfig config;
    private final EventBatcher  batcher;

    public InstructionCollector(SoTraceConfig config, EventBatcher batcher) {
        this.config  = config;
        this.batcher = batcher;
    }

    @Override
    public void onInstruction(Emulator<?> emulator, long address, Instruction ins) {
        int  tid  = getTid(emulator);
        long seq  = batcher.nextSeq();
        long addr = toSoOffset(address);

        batcher.ensureThread(tid, seq == 1 ? 0 : seq - 1);

        boolean isBranch    = isBranchInstruction(ins);
        boolean branchTaken = false; // unidbg does not expose branch-taken here

        batcher.addInstruction(new InstructionEvent(seq, tid, addr, isBranch, branchTaken));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private int getTid(Emulator<?> emulator) {
        try {
            // Multi-thread mode: UniThreadDispatcher.getCurrentThread().getId()
            Object dispatcher = emulator.getClass()
                .getMethod("getThreadDispatcher")
                .invoke(emulator);
            if (dispatcher != null) {
                Object thread = dispatcher.getClass()
                    .getMethod("getRunningThread")
                    .invoke(dispatcher);
                if (thread != null) {
                    Object id = thread.getClass().getMethod("getId").invoke(thread);
                    if (id instanceof Number) {
                        return ((Number) id).intValue();
                    }
                }
            }
        } catch (Exception ignored) {
            // single-thread mode or older unidbg without thread dispatcher
        }
        return 1;
    }

    private long toSoOffset(long address) {
        if (config.soBase == 0) return address;
        long offset = address - config.soBase;
        // negative offset means address is outside the SO region — keep raw
        return offset >= 0 ? offset : address;
    }

    private boolean isBranchInstruction(Instruction ins) {
        if (ins == null) return false;
        String mnemonic = ins.getMnemonic();
        if (mnemonic == null) return false;
        String lc = mnemonic.toLowerCase();
        // ARM/AArch64 branch mnemonics
        return lc.equals("bl")   || lc.equals("blr")  || lc.equals("blx") ||
               lc.equals("b")    || lc.equals("bx")   || lc.equals("ret") ||
               lc.startsWith("b.") || lc.startsWith("b#");
    }
}
