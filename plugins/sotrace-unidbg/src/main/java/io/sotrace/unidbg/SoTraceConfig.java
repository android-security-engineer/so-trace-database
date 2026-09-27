package io.sotrace.unidbg;

/**
 * Configuration for SoTracePlugin.
 *
 * Usage:
 * <pre>{@code
 * SoTraceConfig config = SoTraceConfig.builder()
 *     .serverUrl("http://192.168.1.83:3000")
 *     .traceId(42)
 *     .enableSync(true)
 *     .build();
 * }</pre>
 */
public class SoTraceConfig {

    /** sotrace-server base URL (no trailing slash) */
    final String serverUrl;

    /** Trace ID. 0 = server auto-assigns on first flush. */
    final long traceId;

    /** Flush buffered events automatically when this many events accumulate. */
    final int batchSize;

    /** Hook pthread_mutex_lock/unlock/trylock to capture sync events. */
    final boolean enableSync;

    /** Capture memory reads and writes. */
    final boolean enableMemory;

    /** Capture function call/return events (call stack reconstruction). */
    final boolean enableCalls;

    /** Inject sotrace analysis tools into unidbg's built-in McpServer. */
    final boolean enableMcp;

    /** Runtime base address of the target SO. 0 = trace all memory regions. */
    final long soBase;

    private SoTraceConfig(Builder b) {
        this.serverUrl   = b.serverUrl;
        this.traceId     = b.traceId;
        this.batchSize   = b.batchSize;
        this.enableSync  = b.enableSync;
        this.enableMemory = b.enableMemory;
        this.enableCalls = b.enableCalls;
        this.enableMcp   = b.enableMcp;
        this.soBase      = b.soBase;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String serverUrl  = "http://localhost:3000";
        private long   traceId    = 0;
        private int    batchSize  = 5000;
        private boolean enableSync    = true;
        private boolean enableMemory  = true;
        private boolean enableCalls   = false;
        private boolean enableMcp     = false;
        private long    soBase        = 0;

        public Builder serverUrl(String serverUrl) {
            this.serverUrl = serverUrl;
            return this;
        }

        public Builder traceId(long traceId) {
            this.traceId = traceId;
            return this;
        }

        public Builder batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        public Builder enableSync(boolean enableSync) {
            this.enableSync = enableSync;
            return this;
        }

        public Builder enableMemory(boolean enableMemory) {
            this.enableMemory = enableMemory;
            return this;
        }

        public Builder enableCalls(boolean enableCalls) {
            this.enableCalls = enableCalls;
            return this;
        }

        public Builder enableMcp(boolean enableMcp) {
            this.enableMcp = enableMcp;
            return this;
        }

        public Builder soBase(long soBase) {
            this.soBase = soBase;
            return this;
        }

        public SoTraceConfig build() {
            if (serverUrl == null || serverUrl.isBlank()) {
                throw new IllegalArgumentException("serverUrl must not be blank");
            }
            return new SoTraceConfig(this);
        }

        /**
         * Build the config and immediately attach a new {@link io.sotrace.unidbg.SoTracePlugin}
         * to the given emulator.
         *
         * <pre>{@code
         * SoTracePlugin plugin = SoTracePlugin.builder()
         *     .serverUrl("http://192.168.1.83:3000")
         *     .enableMcp(true)
         *     .attachTo(emulator);
         * }</pre>
         */
        public io.sotrace.unidbg.SoTracePlugin attachTo(com.github.unidbg.Emulator<?> emulator) {
            return io.sotrace.unidbg.SoTracePlugin.fromConfig(build(), emulator);
        }
    }
}
