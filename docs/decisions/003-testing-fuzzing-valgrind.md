# ADR 003: Testing, Fuzzing, and Valgrind

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

Sibling libraries require ctest, dialectic tests, optional libFuzzer harnesses, and valgrind-clean runs.

## Decision

- **ctest** for all unit/integration tests under `tests/`.
- **Smoke** first (create/destroy/policy) — PR-1.
- **Dialectic** client+server buffer exchange when handshake exists — PR-4+.
- **Fuzz** target `fuzz/fuzz_sodchan.c` feeding `sodchan_feed_input` — PR-7.
- **Valgrind** script/CI expectation for all ctest binaries — PR-7.
- Hex **test vectors** for wire format checked into `tests/vectors/` — PR-3.

## Consequences

- **ctest** covers smoke, crypto, wire, dialectic, mitm, auth, channels, and
  **fuzz corpus replay** (`fuzz_sodchan_standalone`).
- **libFuzzer**: `scripts/run_fuzz.sh` builds `fuzz_sodchan` with clang and runs
  a timed campaign over `fuzz/corpus/`.
- **Valgrind**: `scripts/run_valgrind.sh` runs every test binary under memcheck
  (requires `valgrind` + `libc6-dbg` on Debian/Ubuntu).
- **ASan fallback**: `scripts/run_asan_tests.sh` when valgrind/debuginfo is
  unavailable on the host.
- Core parser/handshake/channel changes should not merge without ctest green and
  either a clean valgrind run or ASan ctest + a short fuzz campaign.
