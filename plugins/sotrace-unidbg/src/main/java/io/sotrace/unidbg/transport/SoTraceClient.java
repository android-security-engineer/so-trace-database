package io.sotrace.unidbg.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.sotrace.unidbg.model.TraceEnvelope;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * HTTP client that uploads a {@link TraceEnvelope} to sotrace-server.
 *
 * Uses {@code java.net.http.HttpClient} (Java 11 built-in) to avoid extra deps.
 */
public class SoTraceClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http;
    private final String     serverUrl;

    public SoTraceClient(String serverUrl) {
        // strip trailing slash once
        this.serverUrl = serverUrl.endsWith("/")
            ? serverUrl.substring(0, serverUrl.length() - 1)
            : serverUrl;

        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    /**
     * POST the envelope to {@code /api/v1/traces/import}.
     *
     * @return the trace_id assigned by the server (may differ from the envelope's
     *         trace_id when the server auto-assigns on first import with id=0)
     * @throws IOException on network error or non-200 response
     */
    public long importTrace(TraceEnvelope envelope) throws IOException {
        String json = MAPPER.writeValueAsString(envelope);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl + "/api/v1/traces/import"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(30))
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("import interrupted", e);
        }

        if (resp.statusCode() != 200) {
            throw new IOException("sotrace import failed: HTTP " + resp.statusCode()
                + " — " + resp.body());
        }

        JsonNode node = MAPPER.readTree(resp.body());
        long returnedId = node.path("trace_id").asLong(envelope.traceId);
        return returnedId != 0 ? returnedId : envelope.traceId;
    }

    /**
     * GET an analysis endpoint and return the raw JSON response body.
     * Used by McpToolBridge to proxy analysis tool calls.
     *
     * @param traceId   the trace ID
     * @param endpoint  sub-path after /analyze/threads/, e.g. "races", "deadlocks"
     *                  or "" for the full POST analyze (falls back to GET threads list)
     */
    public String getAnalysis(long traceId, String endpoint) throws IOException {
        String path = endpoint.isEmpty()
            ? "/api/v1/traces/" + traceId + "/analyze/threads"
            : "/api/v1/traces/" + traceId + "/analyze/threads/" + endpoint;
        String url = serverUrl + path;

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(60))
            .GET()
            .build();

        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("analysis request interrupted", e);
        }

        if (resp.statusCode() != 200) {
            throw new IOException("sotrace analysis failed: HTTP " + resp.statusCode()
                + " — " + resp.body());
        }

        return resp.body();
    }
}
