//Uploads SO trace data to sotrace-database for thread analysis.
//@author sotrace-database
//@category Analysis
//@menupath Analysis.sotrace.Upload All Functions
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SoTraceScript extends GhidraScript {

    private long seq = 0;
    private long soBase = 0;

    private final List<String> instructions = new ArrayList<>();
    private final List<String> calls = new ArrayList<>();

    @Override
    public void run() throws Exception {
        String serverUrl = askString(
                "sotrace-server",
                "Enter sotrace-server URL (leave empty to save to file):",
                "http://localhost:3000");

        String outFile = null;
        if (serverUrl == null || serverUrl.trim().isEmpty()) {
            java.io.File f = askFile("Save trace as JSONL", "Save");
            if (f == null) return;
            outFile = f.getAbsolutePath();
            serverUrl = null;
        }

        soBase = currentProgram.getImageBase().getOffset();
        monitor.setMessage("Analyzing functions...");

        FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
        int total = 0;
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            analyzeFunction(funcIter.next());
            total++;
            if (total % 100 == 0) {
                monitor.setMessage("Analyzed " + total + " functions...");
            }
        }

        String envelope = buildEnvelope();

        if (serverUrl != null) {
            long traceId = uploadTrace(serverUrl, envelope);
            popup("sotrace upload complete!\n"
                    + "trace_id=" + traceId + "\n"
                    + "instructions=" + instructions.size() + "\n"
                    + "calls=" + calls.size());
        }

        if (outFile != null) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
                pw.println(envelope);
            }
            popup("Saved to " + outFile);
        }
    }

    private void analyzeFunction(Function func) {
        try {
            AddressSetView body = func.getBody();
            InstructionIterator insns =
                    currentProgram.getListing().getInstructions(body, true);

            while (insns.hasNext() && !monitor.isCancelled()) {
                Instruction insn = insns.next();
                long addr   = insn.getAddress().getOffset();
                long offset = addr - soBase;

                boolean isBranch = insn.getFlowType().isBranch()
                        || insn.getFlowType().isCall()
                        || insn.getFlowType().isTerminal();
                boolean isCall = insn.getFlowType().isCall();

                instructions.add(String.format(
                        "{\"seq\":%d,\"thread_id\":1,\"address\":%d,"
                                + "\"is_branch\":%b,\"branch_taken\":false}",
                        seq++, offset, isBranch));

                if (isCall) {
                    for (Address target : insn.getFlows()) {
                        long calleeOffset = target.getOffset() - soBase;
                        calls.add(String.format(
                                "{\"seq\":%d,\"thread_id\":1,"
                                        + "\"caller_address\":%d,\"callee_address\":%d,"
                                        + "\"depth\":0,\"event_type\":\"Call\"}",
                                seq++, offset, calleeOffset));
                    }
                }
            }
        } catch (Exception ignored) {
            // skip broken functions
        }
    }

    private String buildEnvelope() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"trace_id\":0,");
        sb.append("\"threads\":[{\"thread_id\":1,\"create_step\":0,"
                + "\"parent_thread_id\":0,\"stack_base\":0,\"stack_size\":0,"
                + "\"tls_addr\":0,\"is_jni_attached\":false}],");
        sb.append("\"instructions\":[").append(String.join(",", instructions)).append("],");
        sb.append("\"calls\":[").append(String.join(",", calls)).append("],");
        sb.append("\"memory_writes\":[],\"memory_reads\":[],\"sync_events\":[]}");
        return sb.toString();
    }

    private long uploadTrace(String serverUrl, String body) throws Exception {
        URL url = new URL(serverUrl + "/api/v1/traces/import");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(30_000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        int status = conn.getResponseCode();
        if (status != 200) {
            throw new IOException("HTTP " + status);
        }

        try (BufferedReader br =
                     new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String resp = br.readLine();
            if (resp == null) return 0;
            int idx = resp.indexOf("\"trace_id\":");
            if (idx >= 0) {
                String after = resp.substring(idx + 11).trim();
                String numStr = after.replaceAll("[^0-9].*", "");
                if (!numStr.isEmpty()) return Long.parseLong(numStr);
            }
        }
        return 0;
    }
}
