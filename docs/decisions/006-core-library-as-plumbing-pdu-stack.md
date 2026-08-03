# ADR 006: Core Library as Plumbing — PDU Stack

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

Sibling decision (librest/shaggy ADR 006): core libraries parse and serialize PDUs; applications own policy and I/O.

## Decision

libsodchan is **plumbing only**:

1. Expert at HELLO/KX/AUTH/mux PDU encode/decode and AEAD records.
2. Emits structured `sodchan_event_t` values; does not open channels on its own beyond protocol necessities.
3. Auth **policy** is host: `sodchan_auth_decide` after `SODCHAN_EVENT_AUTH_DEVICE`.
4. No enroll HTTP, no device database, no TLS, no sleep/tarpit.
5. Channel **allowlist** may be consulted as plumbing filter; enrollment association is host-side.

## Consequences

- edgehost and agents remain free to change policy without forking the protocol machine.
- Cleartext lab path is compile-gated and discouraged; real sodium is the preferred lab path.
