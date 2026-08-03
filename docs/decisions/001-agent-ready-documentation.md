# ADR 001: Agent-Ready Documentation Scaffold

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

libsodchan is initialized as a pure C, system-call-free, callback-free state-machine library following sibling patterns (libchssh, librest, libnetconf, shaggy/libhttp2). Coding agents need progressive-disclosure docs from day one.

## Decision

Adopt the agent-ready scaffold:

- `AGENTS.md` as the single source of truth for agents (commands, rules, DoD, status).
- `CLAUDE.md` as symlink to `AGENTS.md`.
- `ARCHITECTURE.md` for module boundaries and invariants.
- `docs/` with README index, DOMAIN.md glossary, and `decisions/` ADRs.
- Record this as ADR 001.
- CMake ≥ 3.20, C11, `-Wall -Wextra -Wpedantic -Werror`, dialectic testing, event-driven API, config structs, no syscalls/callbacks.

## Consequences

- Agents consulting AGENTS.md understand build/test and operating rules immediately.
- Architecture and domain assumptions are explicit.
- Future changes must update relevant docs/ADRs.
