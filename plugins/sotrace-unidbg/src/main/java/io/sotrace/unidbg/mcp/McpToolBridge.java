package io.sotrace.unidbg.mcp;

import com.github.unidbg.Emulator;
import io.sotrace.unidbg.transport.SoTraceClient;

import java.lang.reflect.Method;
import java.util.logging.Logger;

/**
 * Injects sotrace analysis tools into unidbg's built-in McpServer.
 *
 * unidbg ships {@code com.github.unidbg.mcp.McpServer} (SSE / HTTP transport)
 * with {@code addCustomTool(name, description, paramNames, handler)}.  This
 * bridge uses reflection so that the plugin compiles and runs correctly even
 * when the MCP module is absent from the user's unidbg build.
 *
 * Tools injected:
 * <ul>
 *   <li>{@code sotrace_analyze_races}     — race condition detection</li>
 *   <li>{@code sotrace_detect_deadlocks}  — deadlock risk analysis</li>
 *   <li>{@code sotrace_contentions}       — lock contention stats</li>
 *   <li>{@code sotrace_security_audit}    — multi-dimension security workflow</li>
 *   <li>{@code sotrace_perf_bottleneck}   — performance bottleneck workflow</li>
 * </ul>
 *
 * Usage:
 * <pre>{@code
 * McpToolBridge.install(emulator, traceIdSupplier, soTraceClient);
 * }</pre>
 */
public class McpToolBridge {

    private static final Logger LOG = Logger.getLogger(McpToolBridge.class.getName());

    private static final String MCP_SERVER_CLASS = "com.github.unidbg.mcp.McpServer";

    @FunctionalInterface
    public interface TraceIdSupplier {
        long get();
    }

    /**
     * Attempts to find a running McpServer on the emulator and register
     * sotrace tools.  Silently skips if McpServer is unavailable.
     *
     * @param emulator        the unidbg emulator instance
     * @param traceIdSupplier supplier returning the current trace_id
     * @param client          sotrace HTTP client
     */
    public static void install(Emulator<?> emulator, TraceIdSupplier traceIdSupplier, SoTraceClient client) {
        try {
            Class<?> mcpClass = Class.forName(MCP_SERVER_CLASS);
            Object mcpServer  = findMcpServer(emulator, mcpClass);
            if (mcpServer == null) {
                LOG.warning("[sotrace] McpServer not found on emulator — MCP bridge skipped");
                return;
            }

            registerTools(mcpServer, mcpClass, traceIdSupplier, client);
            LOG.info("[sotrace] Registered sotrace analysis tools in unidbg McpServer");

        } catch (ClassNotFoundException e) {
            LOG.warning("[sotrace] com.github.unidbg.mcp.McpServer not available — MCP bridge skipped");
        } catch (Exception e) {
            LOG.warning("[sotrace] McpToolBridge failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static Object findMcpServer(Emulator<?> emulator, Class<?> mcpClass) {
        // unidbg may expose the McpServer via emulator.getMcpServer() or similar
        for (String getter : new String[]{"getMcpServer", "mcpServer", "getMcp"}) {
            try {
                Method m = emulator.getClass().getMethod(getter);
                Object server = m.invoke(emulator);
                if (server != null && mcpClass.isInstance(server)) {
                    return server;
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static void registerTools(
            Object mcpServer,
            Class<?> mcpClass,
            TraceIdSupplier traceIdSupplier,
            SoTraceClient client) throws Exception {

        // Try to find the addCustomTool method — signature may vary across versions
        Method addTool = findAddCustomTool(mcpClass);
        if (addTool == null) {
            LOG.warning("[sotrace] McpServer.addCustomTool not found — skipping tool registration");
            return;
        }

        registerOne(addTool, mcpServer,
            "sotrace_analyze_races",
            "Detect race conditions in the current trace using sotrace",
            traceIdSupplier, client, "races");

        registerOne(addTool, mcpServer,
            "sotrace_detect_deadlocks",
            "Detect deadlock risks and lock cycles in the current trace",
            traceIdSupplier, client, "deadlocks");

        registerOne(addTool, mcpServer,
            "sotrace_contentions",
            "Analyze lock contention statistics for the current trace",
            traceIdSupplier, client, "contentions");

        registerOne(addTool, mcpServer,
            "sotrace_critical_sections",
            "Analyze critical section hold times and longest holders",
            traceIdSupplier, client, "critical-sections");

        registerOne(addTool, mcpServer,
            "sotrace_jni_boundary",
            "Analyze JNI boundary crossings per thread",
            traceIdSupplier, client, "jni-boundary");
    }

    private static void registerOne(
            Method addTool,
            Object mcpServer,
            String name,
            String description,
            TraceIdSupplier traceIdSupplier,
            SoTraceClient client,
            String dimensions) {

        // The handler is a Runnable/Callable/functional-interface depending on unidbg version.
        // We wrap in a java.util.function.Supplier<String> which is most likely accepted.
        java.util.function.Supplier<String> handler = () -> {
            try {
                long traceId = traceIdSupplier.get();
                if (traceId == 0) {
                    return "{\"error\":\"no trace imported yet — call flush() first\"}";
                }
                return client.getAnalysis(traceId, dimensions);
            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage().replace("\"", "'") + "\"}";
            }
        };

        try {
            // Try the most common signature first: addCustomTool(String, String, Supplier)
            addTool.invoke(mcpServer, name, description, handler);
        } catch (Exception e) {
            try {
                // Fallback: addCustomTool(String, String, String[], Supplier)
                addTool.invoke(mcpServer, name, description, new String[0], handler);
            } catch (Exception e2) {
                LOG.warning("[sotrace] Could not register tool '" + name + "': " + e2.getMessage());
            }
        }
    }

    private static Method findAddCustomTool(Class<?> mcpClass) {
        for (Method m : mcpClass.getMethods()) {
            if (m.getName().equals("addCustomTool") || m.getName().equals("registerTool")) {
                return m;
            }
        }
        return null;
    }
}
