# ADR 004: Dialectic Client/Server Testing

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

End-to-end protocol correctness is easiest when two contexts exchange bytes without sockets, proving the state machine is self-contained.

## Decision

Prefer **dialectic tests**: create `SODCHAN_ROLE_CLIENT` and `SODCHAN_ROLE_SERVER`, pump `get_output` of one into `feed_input` of the other until events reach READY / channel data / disconnect.

Deterministic seeds for key material when sodium is available (PR-2+). MITM tests use wrong server secret key against correct pin.

## Consequences

- No network flakes in CI for core protocol tests.
- Host socket integration is a separate layer (edgehost / agent examples).
