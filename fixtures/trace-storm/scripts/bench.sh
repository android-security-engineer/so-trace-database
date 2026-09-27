#!/usr/bin/env sh

# Measure the deterministic trace-storm pipeline. The benchmark intentionally
# keeps all artifacts in a temporary directory and reports only measurements;
# it is suitable for quick local comparisons between debug/release binaries.

set -eu
LC_ALL=C
export LC_ALL

rounds=${1:-31250}
case "$rounds" in
    ''|*[!0-9]*)
        echo "rounds must be a non-negative decimal integer: $rounds" >&2
        exit 2
        ;;
esac
threads=${THREADS:-2}
case "$threads" in
    ''|*[!0-9]*|0)
        echo "THREADS must be a positive decimal integer: $threads" >&2
        exit 2
        ;;
esac
format=${FORMAT:-frida}
case "$format" in
    frida) cli_format=frida-stalker ;;
    unidbg) cli_format=unidbg ;;
    *)
        echo "FORMAT must be one of: frida, unidbg (got $format)" >&2
        exit 2
        ;;
esac

fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repo_dir=$(CDPATH= cd -- "$fixture_dir/../.." && pwd)
capture="$fixture_dir/build/mock-trace-capture"
library="$fixture_dir/build/libtrace_storm.so"

if [ -n "${SOTRACE_BIN:-}" ]; then
    sotrace_bin=$SOTRACE_BIN
    if [ ! -x "$sotrace_bin" ] && [ -x "$repo_dir/$sotrace_bin" ]; then
        sotrace_bin="$repo_dir/$sotrace_bin"
    fi
else
    sotrace_bin="$repo_dir/target/debug/sotrace"
fi

if [ ! -x "$capture" ] || [ ! -f "$library" ]; then
    make -C "$fixture_dir" all >&2
fi
if [ ! -x "$sotrace_bin" ]; then
    cargo build --manifest-path "$repo_dir/crates/sotrace-cli/Cargo.toml" >&2
fi

if [ "$rounds" -lt "$threads" ]; then
    expected_threads=$rounds
else
    expected_threads=$threads
fi
instructions=$((rounds * 32))
normalized_events=$((instructions + expected_threads))

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sotrace-trace-storm-bench.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

trace_file="$tmp_dir/trace.jsonl"
data_dir="$tmp_dir/data"
generate_time="$tmp_dir/generate.time"
save_time="$tmp_dir/save.time"
query_time="$tmp_dir/query.time"
analysis_time="$tmp_dir/analysis.time"
trace_id_file="$tmp_dir/trace-id"

if ! { time -p "$capture" "$trace_file" "$rounds" "$threads" "$format" > /dev/null; } 2>"$generate_time"; then
    echo "trace generation failed" >&2
    exit 1
fi
actual_instructions=$(wc -l < "$trace_file" | tr -d ' ')
if [ "$actual_instructions" -ne "$instructions" ]; then
    echo "expected $instructions generated instructions, got $actual_instructions" >&2
    exit 1
fi

if ! { time -p "$sotrace_bin" --data-dir "$data_dir" trace-save "$trace_file" \
    --format "$cli_format" --so "$library" > "$trace_id_file"; } 2>"$save_time"; then
    echo "trace-save failed" >&2
    exit 1
fi
trace_id=$(tr -d '\n' < "$trace_id_file")
case "$trace_id" in
    ''|*[!0-9]*)
        echo "trace-save returned an invalid trace ID: $trace_id" >&2
        exit 1
        ;;
esac

trace_show_result=$("$sotrace_bin" --data-dir "$data_dir" trace-show "$trace_id")
actual_events=$(printf '%s\n' "$trace_show_result" | sed -n 's/^  event_count  : //p')
if [ "$actual_events" != "$normalized_events" ]; then
    echo "expected $normalized_events normalized events, got $actual_events" >&2
    exit 1
fi

if ! { time -p "$sotrace_bin" --data-dir "$data_dir" query \
    --trace-id "$trace_id" address 0x1000 > /dev/null; } 2>"$query_time"; then
    echo "persisted address query failed" >&2
    exit 1
fi
if ! { time -p "$sotrace_bin" --data-dir "$data_dir" analyze \
    --trace-id "$trace_id" --only lifecycle --json > /dev/null; } 2>"$analysis_time"; then
    echo "persisted lifecycle analysis failed" >&2
    exit 1
fi

jsonl_bytes=$(wc -c < "$trace_file" | tr -d ' ')
blob_file="$data_dir/trace/$trace_id.bincode.zst"
if [ ! -f "$blob_file" ]; then
    echo "persisted trace blob is missing: $blob_file" >&2
    exit 1
fi
blob_bytes=$(wc -c < "$blob_file" | tr -d ' ')

real_seconds() {
    awk '$1 == "real" { print $2; exit }' "$1"
}

generate_seconds=$(real_seconds "$generate_time")
save_seconds=$(real_seconds "$save_time")
query_seconds=$(real_seconds "$query_time")
analysis_seconds=$(real_seconds "$analysis_time")
for seconds in "$generate_seconds" "$save_seconds" "$query_seconds" "$analysis_seconds"; do
    if [ -z "$seconds" ]; then
        echo "failed to read real time from benchmark output" >&2
        exit 1
    fi
done

compression_ratio=$(awk -v raw="$jsonl_bytes" -v compressed="$blob_bytes" \
    'BEGIN { if (compressed > 0) printf "%.2fx", raw / compressed; else print "n/a" }')
generation_rate=$(awk -v n="$instructions" -v s="$generate_seconds" \
    'BEGIN { if (s > 0) printf "%.0f", n / s; else print "n/a" }')
import_rate=$(awk -v n="$normalized_events" -v s="$save_seconds" \
    'BEGIN { if (s > 0) printf "%.0f", n / s; else print "n/a" }')

printf '%s\n' "trace-storm benchmark"
printf '  format              : %s\n' "$format"
printf '  rounds              : %s\n' "$rounds"
printf '  threads             : %s\n' "$threads"
printf '  instructions        : %s\n' "$instructions"
printf '  normalized_events   : %s\n' "$normalized_events"
printf '  jsonl_bytes         : %s\n' "$jsonl_bytes"
printf '  bincode_zst_bytes   : %s\n' "$blob_bytes"
printf '  compression_ratio   : %s (JSONL / blob)\n' "$compression_ratio"
printf '  generate_seconds    : %s\n' "$generate_seconds"
printf '  trace_save_seconds  : %s\n' "$save_seconds"
printf '  query_seconds       : %s\n' "$query_seconds"
printf '  lifecycle_seconds   : %s\n' "$analysis_seconds"
printf '  generate_inst_sec   : %s\n' "$generation_rate"
printf '  import_event_sec    : %s\n' "$import_rate"
printf '  trace_id            : %s\n' "$trace_id"
