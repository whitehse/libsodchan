# ADR 002: Event-Loop Compatibility

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

edgehost uses io_uring; cpe_agent uses libuv/poll; mobile uses platform TLS stacks. The transport library must not assume a particular event loop.

## Decision

libsodchan is **event-loop agnostic**:

- No blocking I/O or internal threads.
- Host feeds bytes with `sodchan_feed_input`, drains with `sodchan_get_output`, polls with `sodchan_next_event`.
- Compatible with io_uring, libuv, libev, poll/select, and mobile run loops that supply plaintext buffers after TLS.

## Consequences

- Same library binary works on host, CPE, and mobile (when sodium is linked).
- Integration tests use dialectic buffer exchange without sockets (ADR 004).
