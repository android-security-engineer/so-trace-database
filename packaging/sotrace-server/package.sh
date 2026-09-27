#!/bin/sh
# Stage the already-built sotrace-server binary and start that copy.
# Usage: packaging/sotrace-server/package.sh
# Requires SOTRACE_AUTH_TOKEN. Writes nothing into the git tree.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
src="$root/target/release/sotrace-server"
if [ ! -x "$src" ]; then
  echo "missing $src; build sotrace-server --release first" >&2
  exit 1
fi

stage=$(mktemp -d)
cp "$src" "$stage/sotrace-server"
chmod +x "$stage/sotrace-server"
printf '%s\n' 'sotrace-server' > "$stage/PACKAGE"

if [ -z "${SOTRACE_AUTH_TOKEN:-}" ]; then
  echo "SOTRACE_AUTH_TOKEN is required" >&2
  exit 1
fi
if [ -z "${SOTRACE_DATA_DIR:-}" ]; then
  echo "SOTRACE_DATA_DIR is required" >&2
  exit 1
fi
if [ -z "${SOTRACE_BIND:-}" ]; then
  echo "SOTRACE_BIND is required" >&2
  exit 1
fi

echo "package=$stage"
echo "binary=$stage/sotrace-server"
exec "$stage/sotrace-server"
