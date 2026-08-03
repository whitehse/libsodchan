# ADR 017: Normative Wire Format (suite V1)

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

PR-4 must implement HELLO / KX / secretstream / AUTH without inventing bytes. Two independent implementations (or rewrites) must interoperate from checked-in vectors.

## Decision

This ADR is the **normative** byte-level specification for `SODCHAN_SUITE_V1`. Implementation lives in `src/sodchan_wire.c` / `sodchan_wire.h`. Golden vectors: `tests/vectors/handshake_v1.hex`.

### Principles

- Multi-byte integers: **big-endian**.
- Cleartext phase: length-prefixed **HELLO** only.
- After HELLO exchange + server identity proof + KX + secretstream headers: encrypted records; each plaintext is **one** mux/AUTH PDU.
- No algorithm negotiation: peer suite/version must match or hard-fail.
- Domain separation strings are ASCII without trailing NUL on the wire.

### Constants

| Name | Value |
|------|-------|
| `SODCHAN_MAGIC` | `0x5343` (`'S''C'`) |
| `SODCHAN_PROTO_VERSION` | `1` |
| `SODCHAN_SUITE_V1` | `1` |
| HELLO body length | **140** fixed |
| Clear frame max body | 512 |
| `SODCHAN_DOM_SERVER_HELLO` | `"sodchan-v1-server-hello"` (**23** bytes) |
| `SODCHAN_DOM_CLIENT_AUTH` | `"sodchan-v1-client-auth"` (**22** bytes) |
| `SODCHAN_DOM_SS_C2S` | `"sodchan-ss-c2s-v1"` (17) |
| `SODCHAN_DOM_SS_S2C` | `"sodchan-ss-s2c-v1"` (17) |
| `SODCHAN_T_HELLO_LEN` | **123** = 23+2+2+32+32+32 |

> Note: an earlier design draft said server-hello DOM is 22 bytes; the **string literal is authoritative** (23).

### Cleartext framing

```text
u32be length (L) | body[L]
L ∈ 1..512; L=0 illegal
```

HELLO frames use `L = 140`.

### HELLO body (140 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | magic = `0x5343` |
| 2 | 2 | proto_version |
| 4 | 2 | suite_id |
| 6 | 2 | role: 0=server, 1=client |
| 8 | 4 | flags (v1: 0) |
| 12 | 32 | eph_pk (`crypto_kx` public) |
| 44 | 32 | id_pk (Ed25519 public) |
| 76 | 64 | id_sig (server: sig over `T_hello`; client: zeros) |

### `T_hello` transcript (server signs)

```text
T_hello =
  "sodchan-v1-server-hello" ||   # 23
  u16be(proto_version) ||
  u16be(suite_id) ||
  client_eph_pk ||               # 32
  server_eph_pk ||               # 32
  server_id_pk                   # 32
```

`id_sig = crypto_sign_detached(T_hello, server_id_sk)` (PR-4).

Client: pin-check `id_pk`, verify `id_sig`, **then** `crypto_kx`.

### Secretstream header order (post-HELLO)

1. Client → server: `u32be(24) | ss_header_c2s`
2. Server → client: `u32be(24) | ss_header_s2c`

Then ciphertext frames: `u32be(ct_len) | ct` (one secretstream message each).  
Inner plaintext: single PDU.

Session keys: BLAKE2b-32 labeled KDF (ADR 014).

### AUTH PDUs (encrypted)

| Type | Code | Layout |
|------|------|--------|
| AUTH_DEVICE | 20 | `pk[32] \| sig[64] \| u8 ulen \| user \| u8 dlen \| device` |
| AUTH_OK | 21 | `u16be claims_len \| claims` (≤1024) |
| AUTH_FAIL | 22 | `u8 reason \| u8 msg_len \| msg` — **wire always reason=0 (UNSPEC), msg_len=0** |

`T_auth`:

```text
"sodchan-v1-client-auth" || T_hello || client_id_pk ||
  u8(username_len) || username || u8(device_id_len) || device_id
```

### Mux PDU types (post-AUTH)

| Type | Code | Body |
|------|------|------|
| CHANNEL_OPEN | 1 | `u32 sender, u32 init_win, u32 max_pkt, u8 nlen, name` |
| CHANNEL_OPEN_CONFIRM | 2 | `u32 sender, u32 recipient, u32 init_win, u32 max_pkt` |
| CHANNEL_OPEN_FAIL | 3 | `u32 recipient, u32 reason, u8 mlen, msg` |
| CHANNEL_WINDOW_ADJUST | 4 | `u32 recipient, u32 bytes_to_add` |
| CHANNEL_DATA | 5 | `u32 recipient, u32 data_len, data` |
| CHANNEL_EOF | 6 | `u32 recipient` |
| CHANNEL_CLOSE | 7 | `u32 recipient` |
| PING | 8 | `u32 opaque` |
| PONG | 9 | `u32 opaque` |
| DISCONNECT | 10 | `u32 reason, u8 mlen, msg` |

### Vectors

`tests/vectors/handshake_v1.hex` contains layout goldens for HELLO, frames, `T_hello`, `T_auth`, AUTH_*, and sample mux PDUs. Signature fields may be synthetic patterns for layout tests; PR-4 adds cryptographic MITM vectors.

### Implementation API

Internal header `src/sodchan_wire.h` (not installed): encode/decode helpers used by the state machine and unit tests.

## Consequences

- PR-4 must not change these layouts without a suite version bump.
- Domain length correction (23 vs 22) is locked here and in code `_Static`/sizeof checks.
- Cross-language ports must match golden vectors byte-for-byte.
