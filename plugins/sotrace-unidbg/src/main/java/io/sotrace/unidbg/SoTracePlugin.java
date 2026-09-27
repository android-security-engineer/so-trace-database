package io.sotrace.unidbg;

import com.github.unidbg.Emulator;
import io.sotrace.unidbg.collector.InstructionCollector;
import io.sotrace.unidbg.collector.MemoryCollector;
import io.sotrace.unidbg.collector.SyncHooker;
import io.sotrace.unidbg.mcp.McpToolBridge;
import io.sotrace.unidbg.model.TraceEnvelope;
import io.sotrace.unidbg.transport.EventBatcher;
import io.sotrace.unidbg.transport.SoTraceClient;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main entry point for the sotrace-unidbg plugin.
 *
 * <h2>Minimal usage (one line)</h2>
 * <pre>{@code
 * SoTracePlugin plugin = SoTracePlugin.attach(emulator, "http://192.168.1.83:3000");
 * emulator.callFunction(module, "target_func", args);
 * plugin.flush();
 * System.out.println("trace_id = " + plugin.getTraceId());
 * }</pre>
 *
 * <h2>Builder usage</h2>
 * <pre>{@code
 * SoTracePlugin plugin = SoTracePlugin.builder()
 *     .serverUrl("http://192.168.1.83:3000")
 *     .soBase(0x71000000L)
 *     .enableSync(true)
 *     .enableMcp(true)
 *     .build();
 * plugin.attach(emulator);
 * emulator.callFunction(module, "target_func", args);
 * plugin.flush();
 * plugin.detach();
 * }</pre>
 */
public class SoTracePlugin {

    private static final Logger LOG = Logger.getLogger(SoTracePlugin.class.getName());

    private final SoTraceConfig  config;
    private final EventBatcher   batcher;
    private final SoTraceClient  client;
    private final AtomicLong     currentTraceId;

    private boolean attached = false;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    private SoTracePlugin(SoTraceConfig config) {
        this.config         = config;
        this.batcher        = new EventBatcher();
        this.client         = new SoTraceClient(config.serverUrl);
        this.currentTraceId = new AtomicLong(config.traceId);
    }

    // -------------------------------------------------------------------------
    // Static factory helpers
    // -------------------------------------------------------------------------

    /**
     * Convenience factory: create a plugin with default config (all collectors
     * enabled, sync hooks on), attach it to the emulator, and return it.
     */
    public static SoTracePlugin attach(Emulator<?> emulator, String serverUrl) {
        SoTracePlugin plugin = new SoTracePlugin(
            SoTraceConfig.builder().serverUrl(serverUrl).build()
        );
        plugin.attach(emulator);
        return plugin;
    }

    /** Start building a customised plugin. */
    public static SoTraceConfig.Builder builder() {
        return SoTraceConfig.builder();
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /**
     * Build a plugin from a completed config and attach it.
     * Call this on the object returned by {@link SoTraceConfig.Builder#build()}.
     */
    public static SoTracePlugin fromConfig(SoTraceConfig config, Emulator<?> emulator) {
        SoTracePlugin plugin = new SoTracePlugin(config);
        plugin.attach(emulator);
        return plugin;
    }

    /**
     * Attach all collectors to the given emulator.
     * Must be called before emulation starts.
     */
    public synchronized void attach(Emulator<?> emulator) {
        if (attached) {
            throw new IllegalStateException("SoTracePlugin is already attached");
        }
        attached = true;

        // Instruction tracing — full address range when soBase is unset
        long begin = config.soBase == 0 ? 0L           : config.soBase;
        long end   = config.soBase == 0 ? Long.MAX_VALUE : config.soBase + 0x10000000L;
        emulator.traceCode(begin, end, new InstructionCollector(config, batcher));

        // Memory reads / writes
        if (config.enableMemory) {
            MemoryCollector mc = new MemoryCollector(config, batcher);
            emulator.traceRead(0L, Long.MAX_VALUE, mc);
            emulator.traceWrite(0L, Long.MAX_VALUE, mc);
        }

        // Sync hooks (pthread_mutex_*, pthread_cond_*, pthread_rwlock_*)
        if (config.enableSync) {
            try {
                emulator.getMemory().addHookListener(new SyncHooker(emulator, batcher));
            } catch (Exception e) {
                LOG.warning("[sotrace] Could not install sync hooks: " + e.getMessage());
            }
        }

        // Inject tools into unidbg's built-in McpServer (if present)
        if (config.enableMcp) {
            McpToolBridge.install(emulator, this::getTraceId, client);
        }

        LOG.info("[sotrace] Attached — server=" + config.serverUrl
            + "  memory=" + config.enableMemory
            + "  sync=" + config.enableSync
            + "  mcp=" + config.enableMcp);
    }

    /**
     * Flush all buffered events to sotrace-server (blocking).
     *
     * @return the trace_id confirmed by the server
     * @throws IOException on network failure
     */
    public long flush() throws IOException {
        if (batcher.isEmpty()) {
            return currentTraceId.get();
        }

        TraceEnvelope envelope = batcher.drain(currentTraceId.get());
        long assignedId = client.importTrace(envelope);
        currentTraceId.set(assignedId);

        LOG.info("[sotrace] Flushed  trace_id=" + assignedId
            + "  instructions=" + envelope.instructions.size()
            + "  memWrites=" + envelope.memoryWrites.size()
            + "  memReads=" + envelope.memoryReads.size()
            + "  syncEvents=" + envelope.syncEvents.size());

        // Auto-flush if batcher filled up during the flush window
        if (batcher.size() >= config.batchSize) {
            return flush();
        }

        return assignedId;
    }

    /**
     * Non-blocking variant of {@link #flush()}.
     * Errors are logged but not rethrown.
     */
    public CompletableFuture<Long> flushAsync() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return flush();
            } catch (IOException e) {
                LOG.log(Level.WARNING, "[sotrace] Async flush failed", e);
                return currentTraceId.get();
            }
        });
    }

    /**
     * Flush remaining events and release all listeners.
     */
    public void detach() {
        if (!batcher.isEmpty()) {
            try {
                flush();
            } catch (IOException e) {
                LOG.log(Level.WARNING, "[sotrace] Final flush on detach failed", e);
            }
        }
        attached = false;
        LOG.info("[sotrace] Detached  trace_id=" + currentTraceId.get());
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    /** The trace_id last confirmed by the server. 0 if flush() has never succeeded. */
    public long getTraceId() {
        return currentTraceId.get();
    }

    /** Access the internal batcher (advanced / testing use). */
    public EventBatcher getBatcher() {
        return batcher;
    }

    /** Access the HTTP client (advanced / testing use). */
    public SoTraceClient getClient() {
        return client;
    }
}
