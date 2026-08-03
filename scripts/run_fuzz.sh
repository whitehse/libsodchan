#!/usr/bin/env bash
# Build and run libFuzzer target (PR-7).
#
# Usage (from repo root):
#   ./scripts/run_fuzz.sh [seconds]
#
# Defaults to 30 seconds. Uses clang-19 if available, else clang.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECONDS_RUN="${1:-30}"
BUILD="$ROOT/build-fuzz"
CORPUS="$ROOT/fuzz/corpus"
CLANG="${CC:-}"

if [[ -z "$CLANG" ]]; then
    if command -v clang-19 >/dev/null 2>&1; then
        CLANG=clang-19
        CLANGXX=clang++-19
    elif command -v clang >/dev/null 2>&1; then
        CLANG=clang
        CLANGXX=clang++
    else
        echo "clang not found; cannot build libFuzzer harness" >&2
        exit 127
    fi
else
    CLANGXX="${CXX:-clang++}"
fi

mkdir -p "$CORPUS"
cmake -B "$BUILD" -S "$ROOT" \
    -DENABLE_FUZZ=ON \
    -DCMAKE_C_COMPILER="$CLANG" \
    -DCMAKE_CXX_COMPILER="$CLANGXX" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$BUILD" --target fuzz_sodchan -j"$(nproc 2>/dev/null || echo 2)"

# Write new units under build-fuzz so the tracked seed corpus stays clean.
ART="$BUILD/corpus-art"
mkdir -p "$ART"
# Seed from tracked corpus; mutations accumulate in ART.
cp -a "$CORPUS/." "$ART/" 2>/dev/null || true

echo "=== fuzz_sodchan max_total_time=${SECONDS_RUN}s ==="
"$BUILD/fuzz_sodchan" "$ART" \
    -max_total_time="$SECONDS_RUN" \
    -print_final_stats=1 \
    -artifact_prefix="$BUILD/crash-"

echo "=== fuzz finished (no crash) ==="
