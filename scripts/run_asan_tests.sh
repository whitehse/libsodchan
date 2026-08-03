#!/usr/bin/env bash
# Rebuild tests with AddressSanitizer and run ctest (PR-7 memory bar when
# valgrind/debuginfo is unavailable).
#
# Usage (from repo root):
#   ./scripts/run_asan_tests.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build-asan"

if command -v clang-19 >/dev/null 2>&1; then
    CC=clang-19
    CXX=clang++-19
elif command -v clang >/dev/null 2>&1; then
    CC=clang
    CXX=clang++
else
    CC=gcc
    CXX=g++
fi

export CC CXX
cmake -B "$BUILD" -S "$ROOT" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build "$BUILD" -j"$(nproc 2>/dev/null || echo 2)"
ctest --test-dir "$BUILD" --output-on-failure

echo "=== ASan/UBSan ctest clean ==="
