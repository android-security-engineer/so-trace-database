package io.sotrace.unidbg.collector;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.memory.SvcMemory;
import io.sotrace.unidbg.model.SyncEvent;
import io.sotrace.unidbg.transport.EventBatcher;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Map;

/**
 * Hooks libc pthread_mutex_* and pthread_cond_* functions via unidbg's
 * {@link HookListener} to capture synchronization events.
 *
 * Uses unidbg's {@link Backend} CodeHook (available since 0.9.7) to install an
 * inline hook at the function entry, reading the mutex pointer from register
 * x0 (AArch64) or r0 (ARM32).
 *
 * Register with:
 * <pre>{@code
 * emulator.getMemory().addHookListener(new SyncHooker(emulator, batcher));
 * }</pre>
 */
public class SyncHooker implements HookListener {

    /** Maps pthread symbol name → sotrace SyncEventType string */
    private static final Map<String, String> SYNC_TYPES = Map.ofEntries(
        Map.entry("pthread_mutex_lock",      "MutexLock"),
        Map.entry("pthread_mutex_unlock",    "MutexUnlock"),
        Map.entry("pthread_mutex_trylock",   "MutexTryLock"),
        Map.entry("pthread_mutex_timedlock", "MutexLock"),
        Map.entry("pthread_rwlock_rdlock",   "RwLockRead"),
        Map.entry("pthread_rwlock_wrlock",   "RwLockWrite"),
        Map.entry("pthread_rwlock_unlock",   "RwLockUnlock"),
        Map.entry("pthread_cond_wait",       "CondvarWait"),
        Map.entry("pthread_cond_signal",     "CondvarSignal"),
        Map.entry("pthread_cond_broadcast",  "CondvarBroadcast")
    );

    private final Emulator<?> emulator;
    private final EventBatcher batcher;

    public SyncHooker(Emulator<?> emulator, EventBatcher batcher) {
        this.emulator = emulator;
        this.batcher  = batcher;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long oldAddress) {
        String syncType = SYNC_TYPES.get(symbolName);
        if (syncType == null) {
            return 0; // not a symbol we care about — do not replace
        }

        installEntryHook(symbolName, syncType, oldAddress);
        return 0; // 0 = keep original function, just monitor
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private void installEntryHook(String symbolName, String syncType, long fnAddress) {
        if (fnAddress == 0) return;

        try {
            Backend backend = emulator.getBackend();
            boolean is64 = emulator.is64Bit();

            backend.hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    if (address != fnAddress) return;
                    try {
                        long mutexAddr;
                        if (is64) {
                            // AArch64: first argument in x0
                            mutexAddr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                        } else {
                            // ARM32: first argument in r0
                            mutexAddr = backend.reg_read(ArmConst.UC_ARM_REG_R0).longValue() & 0xFFFFFFFFL;
                        }

                        long seq = batcher.nextSeq();
                        batcher.addSync(new SyncEvent(seq, 1, syncType, mutexAddr, "Success"));
                    } catch (Exception ignored) {
                        // best-effort: don't crash unidbg emulation
                    }
                }
            }, fnAddress, fnAddress + 4, null);

        } catch (Exception e) {
            // Graceful degradation: if the hook API is unavailable (older unidbg),
            // record the event at symbol-bind time with addr=0.
            long seq = batcher.nextSeq();
            batcher.addSync(new SyncEvent(seq, 1, syncType, 0L, "Success"));
        }
    }
}
