#!/bin/sh
# Build libreveal.so, run it, and prove the return value is absent from the
# shared object but present after `sotrace trace-save` + `sotrace query`.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
fix="$root/fixtures/runtime-reveal"
make -C "$fix" all

so="$fix/build/libreveal.so"
run="$fix/build/reveal-run"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$run" "$so" "$work/trace.json" > "$work/fact.txt"
fact=$(tr -d '[:space:]' < "$work/fact.txt")
echo "runtime_fact=$fact"

python3 - "$so" "$fact" << 'PY'
import pathlib, sys
blob = pathlib.Path(sys.argv[1]).read_bytes()
fact = int(sys.argv[2])
needles = [
    str(fact).encode(),
    f"{fact:x}".encode(),
    f"{fact:X}".encode(),
    f"0x{fact:x}".encode(),
    fact.to_bytes(4, "little"),
    fact.to_bytes(4, "big"),
    fact.to_bytes(8, "little"),
    fact.to_bytes(8, "big"),
]
for needle in needles:
    if needle in blob:
        raise SystemExit(f"fact leaked into {sys.argv[1]} as {needle!r}")
print("static_scan=miss")
PY

if strings "$so" | grep -F -x "$fact" >/dev/null; then
    echo "strings printed the fact" >&2
    exit 1
fi
echo "strings_scan=miss"

if [ -n "${SOTRACE_BIN:-}" ]; then
    bin=$SOTRACE_BIN
else
    cargo build -p sotrace-cli --manifest-path "$root/Cargo.toml"
    bin="$root/target/debug/sotrace"
fi

id=$("$bin" --data-dir "$work/db" trace-save "$work/trace.json")
echo "trace_id=$id"
"$bin" --data-dir "$work/db" query --trace-id "$id" register 0 1 | tee "$work/query.json"

python3 - "$work/query.json" "$fact" << 'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
fact = int(sys.argv[2])
if doc.get("value") != fact:
    raise SystemExit(f"query value {doc.get('value')!r} != runtime fact {fact}")
if doc.get("value_hex") != hex(fact):
    raise SystemExit(f"query hex {doc.get('value_hex')!r} != {hex(fact)}")
print("query_fact=match")
PY
