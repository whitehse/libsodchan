# ADR 009: Consistent Protocol Interfaces

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

libchssh, librest, libnetconf, and libhttp2 share a family of interfaces so hosts can compose stacks predictably.

## Decision

libsodchan follows the sibling interface shape:

| Pattern | libsodchan |
|---------|------------|
| Role enum | `sodchan_role_t` SERVER/CLIENT |
| Config struct | `sodchan_config_t` (zero-init defaults) |
| Create | `sodchan_create(role, &cfg)` |
| Destroy / reset | `sodchan_destroy` / `sodchan_reset` |
| Input | `sodchan_feed_input` → bytes consumed |
| Output | `sodchan_get_output` → bytes written |
| Events | `sodchan_next_event` → 0/1 + `sodchan_event_t` |
| State | `sodchan_current_state` |
| Policy hook | `sodchan_auth_decide` |

Return codes: `SODCHAN_OK` and negative error classes (`PARAM`, `STATE`, `WINDOW`, `FULL`, …).

## Consequences

- Host authors familiar with libchssh can adopt sodchan with minimal cognitive load.
- Future language bindings can wrap one consistent surface.
