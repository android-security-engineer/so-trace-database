#!/usr/bin/env sh

# Generate a deterministic trace with the mock SO, persist it through the CLI,
# and assert the most important replay/index invariants. This intentionally
# relies only on POSIX shell utilities so a fresh development machine does not
# need jq or another JSON tool to validate the fixture.

set -eu

rounds=${1:-10}
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
else
    sotrace_bin="$repo_dir/target/debug/sotrace"
fi

if [ ! -x "$sotrace_bin" ]; then
    cargo build --manifest-path "$repo_dir/crates/sotrace-cli/Cargo.toml" >&2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sotrace-trace-storm.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

trace_file="$tmp_dir/trace.jsonl"
data_dir="$tmp_dir/data"
"$capture" "$trace_file" "$rounds" "$threads" "$format" >&2

expected_instructions=$((rounds * 32))
actual_instructions=$(wc -l < "$trace_file" | tr -d ' ')
if [ "$actual_instructions" -ne "$expected_instructions" ]; then
    echo "expected $expected_instructions generated instructions, got $actual_instructions" >&2
    exit 1
fi

trace_id=$("$sotrace_bin" --data-dir "$data_dir" trace-save "$trace_file" \
    --format "$cli_format" --so "$library")
case "$trace_id" in
    ''|*[!0-9]*)
        echo "trace-save returned an invalid trace ID: $trace_id" >&2
        exit 1
        ;;
esac

if [ "$rounds" -lt "$threads" ]; then
    expected_threads=$rounds
else
    expected_threads=$threads
fi
expected_events=$((expected_instructions + expected_threads))

trace_show_result=$("$sotrace_bin" --data-dir "$data_dir" trace-show "$trace_id")
actual_events=$(printf '%s\n' "$trace_show_result" |
    sed -n 's/^  event_count  : //p')
if [ "$actual_events" != "$expected_events" ]; then
    echo "expected $expected_events normalized events, got $actual_events" >&2
    printf '%s\n' "$trace_show_result" >&2
    exit 1
fi

address_result=$("$sotrace_bin" --data-dir "$data_dir" query --trace-id "$trace_id" address 0x1000)
if ! printf '%s\n' "$address_result" | grep -q "\"step_count\": $rounds"; then
    echo "address index result did not contain one 0x1000 event per round" >&2
    printf '%s\n' "$address_result" >&2
    exit 1
fi
thread_index=0
while [ "$thread_index" -lt "$expected_threads" ]; do
    thread_id=$((1000 + thread_index))
    if ! printf '%s\n' "$address_result" | grep -q "\"thread_id\": $thread_id"; then
        echo "address index result is missing mock thread $thread_id" >&2
        exit 1
    fi
    thread_index=$((thread_index + 1))
done

instructions_result=$("$sotrace_bin" --data-dir "$data_dir" query \
    --trace-id "$trace_id" instructions 0 "$expected_instructions")
if ! printf '%s\n' "$instructions_result" | grep -q "\"count\": $expected_instructions"; then
    echo "instruction range returned an incorrect count" >&2
    printf '%s\n' "$instructions_result" >&2
    exit 1
fi
expected_branches=$((rounds * 4))
actual_branches=$(printf '%s\n' "$instructions_result" |
    grep -o '"is_branch": true' | wc -l | tr -d ' ')
if [ "$actual_branches" -ne "$expected_branches" ]; then
    echo "expected $expected_branches branch instructions, got $actual_branches" >&2
    exit 1
fi

branch_address_result=$("$sotrace_bin" --data-dir "$data_dir" query \
    --trace-id "$trace_id" address 0x101c)
if ! printf '%s\n' "$branch_address_result" | grep -q "\"step_count\": $rounds"; then
    echo "branch address index returned an incorrect count" >&2
    printf '%s\n' "$branch_address_result" >&2
    exit 1
fi
if [ "$rounds" -gt 0 ]; then
    first_branch_result=$("$sotrace_bin" --data-dir "$data_dir" query \
        --trace-id "$trace_id" instruction 7)
    if ! printf '%s\n' "$first_branch_result" | grep -q '"is_branch": true'; then
        echo "branch metadata lost is_branch at address 0x101c" >&2
        printf '%s\n' "$first_branch_result" >&2
        exit 1
    fi
    if ! printf '%s\n' "$first_branch_result" | grep -q '"branch_taken":'; then
        echo "branch metadata lost branch_taken at address 0x101c" >&2
        printf '%s\n' "$first_branch_result" >&2
        exit 1
    fi
fi

# The direct adapter path and the persisted replay path must expose the same
# address index. This catches divergence between parse() and parse_reader().
direct_address_file="$tmp_dir/direct-address.json"
persisted_address_file="$tmp_dir/persisted-address.json"
"$sotrace_bin" --data-dir "$data_dir" query "$trace_file" \
    --format "$cli_format" --so "$library" address 0x1000 > "$direct_address_file"
"$sotrace_bin" --data-dir "$data_dir" query --trace-id "$trace_id" \
    address 0x1000 > "$persisted_address_file"
if ! cmp -s "$direct_address_file" "$persisted_address_file"; then
    echo "direct adapter and persisted replay address results differ" >&2
    diff -u "$direct_address_file" "$persisted_address_file" >&2 || true
    exit 1
fi

threads_result=$("$sotrace_bin" --data-dir "$data_dir" query --trace-id "$trace_id" threads)
thread_ids=
thread_index=0
while [ "$thread_index" -lt "$expected_threads" ]; do
    thread_id=$((1000 + thread_index))
    thread_ids="$thread_ids $thread_id"
    thread_index=$((thread_index + 1))
done
for thread_id in $thread_ids; do
    if ! printf '%s\n' "$threads_result" | grep -q "\"thread_id\": $thread_id"; then
        echo "thread query is missing mock thread $thread_id" >&2
        exit 1
    fi
done

# Exercise the analyzer against the persisted event stream as well, rather
# than only querying the reconstructed indexes. The lifecycle analyzer must
# recover the same set of active threads regardless of whether the source
# format carries explicit thread-create records (Unidbg) or relies on
# inference from the instruction stream (Frida Stalker), making this a
# deterministic assertion for the mock's alternating thread IDs either way.
lifecycle_result=$("$sotrace_bin" --data-dir "$data_dir" analyze \
    --trace-id "$trace_id" --only lifecycle --json)
if ! printf '%s\n' "$lifecycle_result" | grep -q '"lifecycle"'; then
    echo "lifecycle analysis did not return a lifecycle result" >&2
    exit 1
fi
for thread_id in $thread_ids; do
    if ! printf '%s\n' "$lifecycle_result" | grep -q "\"thread_id\": $thread_id"; then
        echo "lifecycle analysis is missing mock thread $thread_id" >&2
        exit 1
    fi
done

printf 'verified trace-storm: %s instructions, trace ID %s\n' \
    "$expected_instructions" "$trace_id"
