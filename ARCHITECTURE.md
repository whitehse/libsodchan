# ARCHITECTURE.md — libsodchan

## Purpose

libsodchan is a **plumbing-only** protocol library: byte buffers and events in, byte buffers and events out. It implements an SSH-like multiplexed channel transport over a **fixed libsodium suite** (X25519 KX, Ed25519 identity, secretstream AEAD). Callers (edgehost, cpe_agent, ecoec-mobile) own TCP/TLS and policy.

## Module map

| Path | Role |
|------|------|
| `include/sodchan.h` | Public API |
| `src/sodchan.c` | State machine, channels, I/O buffers |
| `src/sodchan_crypto.c` | Sodium keygen, SCSK, fingerprints, SS KDF |
| `src/sodchan_wire.c` / `sodchan_wire.h` | PDU encode/decode (ADR 017) |
| `src/sodchan_internal.h` | Private context |
| `cmake/FindSodium.cmake` | Locate libsodium |
| `tests/vectors/handshake_v1.hex` | Golden wire layouts |

## Invariants

1. **No syscalls** — no `socket`, `read`, `write`, `sleep`, `getrandom` wrappers that block hosts.
2. **No callbacks** — host polls `next_event` and drains `get_output`.
3. **Fail-closed pin** — CLIENT create requires `server_id_pk` unless `accept_any_server_pk=1`.
4. **No wire passwords** — device pubkey auth only; enroll is HTTPS outside this library.
5. **Mandatory server identity proof** (PR-4) — Ed25519 sig over HELLO transcript including both ephemerals before AUTH.
6. **lab_mode** compile-gated (`SODCHAN_ALLOW_LAB_CLEARTEXT`, default off).

## Roles and ports (host responsibility)

| Port | Transport | Typical client |
|------|-----------|----------------|
| 4334 | libchssh E7 NETCONF | Field gear (not this library) |
| 4335 | libchssh CPE legacy | Dual-stack migration |
| **4336** | sodchan **raw** | cpe_agent |
| **4337** | TLS → sodchan plaintext | mobile |
| 443 | HTTPS enroll + assets | mobile / SPA |

## State machine

```
create → HELLO → SS_HEADER → AUTH → READY → DRAINING → CLOSED
                                      ↘ ERROR
```

PR-4 implements through `AUTH` (encrypted channel ready; AUTH PDUs in PR-5).

## Sibling relationship

| Library | Scope |
|---------|--------|
| **libchssh** | OpenSSH-shaped Call Home SSH; E7 stays here; CPE migrates off |
| **libnetconf** | NETCONF PDUs over SSH channel |
| **librest** | REST over HTTP/2 plumbing |
| **libsodchan** | First-party sodium channels for CPE + mobile |

## Deliberate absences

- No OpenSSH wire interop
- No image/SPA asset framing (HTTPS)
- No user database or enroll HTTP
- No sockets or TLS inside the library
