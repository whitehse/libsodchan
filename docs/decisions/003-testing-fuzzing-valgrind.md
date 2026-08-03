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

- PR-1 ships smoke only; later PRs expand coverage without changing the contract.
