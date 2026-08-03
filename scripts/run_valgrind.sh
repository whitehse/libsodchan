#!/usr/bin/env bash
# Run all sodchan ctest binaries under Valgrind (ADR 003 / PR-7).
#
# Usage (from repo root):
#   ./scripts/run_valgrind.sh [build-dir]
#
# Requires: valgrind, libc6-dbg (Debian/Ubuntu). Exits non-zero on leaks
# or invalid memory use.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-$ROOT/build}"
VECTORS="$ROOT/tests/vectors/handshake_v1.hex"

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind not found in PATH; install valgrind and libc6-dbg" >&2
    echo "  Debian/Ubuntu: sudo apt-get install valgrind libc6-dbg" >&2
    exit 127
fi

if [[ ! -d "$BUILD" ]]; then
    echo "build dir missing: $BUILD (run cmake -B build -S . && cmake --build build)" >&2
    exit 1
fi

VG=(valgrind
    --tool=memcheck
    --leak-check=full
    --show-leak-kinds=definite,possible
    --errors-for-leak-kinds=definite
    --error-exitcode=99
    --track-origins=yes
    --quiet
)

run_one() {
    local bin="$1"
    shift
    if [[ ! -x "$bin" ]]; then
        echo "SKIP (missing): $bin"
        return 0
    fi
    echo "=== valgrind $(basename "$bin") ==="
    "${VG[@]}" "$bin" "$@"
}

cd "$BUILD"

run_one ./sodchan_smoke_test
run_one ./sodchan_crypto_test
run_one ./sodchan_wire_test "$VECTORS"
run_one ./sodchan_dialectic_test
run_one ./sodchan_mitm_pin_test
run_one ./sodchan_auth_test
run_one ./sodchan_channels_test

if [[ -x ./fuzz_sodchan_standalone ]]; then
    run_one ./fuzz_sodchan_standalone "$ROOT/fuzz/corpus/"*
fi

echo "=== all valgrind runs clean ==="
