# ADR 014: Fixed libsodium Crypto Suite

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

libsodchan replaces OpenSSH-shaped negotiation (libchssh) for first-party CPE and mobile. Field gear interop is not required. We need a small, audited, fixed algorithm set with clear key encodings and domain-separated session keys.

## Decision

### Suite `SODCHAN_SUITE_V1` (no negotiation)

| Layer | Primitive | libsodium API |
|-------|-----------|---------------|
| Identity | Ed25519 | `crypto_sign_*` |
| Ephemeral KX | X25519 | `crypto_kx_*` |
| Outer records | XChaCha20-Poly1305 secretstream | `crypto_secretstream_xchacha20poly1305_*` |
| Transcript / KDF | BLAKE2b | `crypto_generichash` |
| Fingerprint hash | SHA-256 | `crypto_hash_sha256` |
| Constant-time compare | | `sodium_memcmp` |

Peer `suite_id` must equal local suite or hard-fail (wire ADR 017 / PR-3).

### Key sizes and encoding (K4)

| Object | Size / format |
|--------|----------------|
| Public key | 32 raw bytes |
| Secret key | **64 raw bytes** sodium `crypto_sign_SECRETKEYBYTES` |
| Seed | 32 bytes; on disk only as **`SCSK\x01` + seed** (37 bytes total) |
| Fingerprint | `SHA256:` + unpadded base64 of SHA-256(pk) |

Bare 32-byte seed files without magic are **rejected** to avoid mixed formats.

### Session key derivation (before secretstream)

After `crypto_kx_*_session_keys`:

```text
ss_key_c2s = BLAKE2b-32( client_to_server_kx_key || "sodchan-ss-c2s-v1" )
ss_key_s2c = BLAKE2b-32( server_to_client_kx_key || "sodchan-ss-s2c-v1" )
```

Never feed raw `crypto_kx` keys into secretstream without this labeled KDF.

### Server identity binding (K16 — handshake PR-4)

Server Ed25519-signs a HELLO transcript including **both** ephemeral public keys before the client treats KX as authentic. Documented here so suite choice and binding stay one decision set; wire bytes in ADR 017.

### Dependency

- **libsodium** required (CMake `find_package(Sodium REQUIRED)` via `cmake/FindSodium.cmake`).
- Optional `SODIUM_ROOT` or `third_party/sodium-prefix/usr` for headers/libs when system `-dev` is missing.
- No OpenSSL / mbedTLS in libsodchan.

## Consequences

- Smaller state machine than libchssh production path.
- PR-2 ships keygen, SCSK, fingerprints, and `sodchan_crypto_ss_key_derive`.
- PR-3/4 lock wire layout and full handshake using this suite only.
- CPE/mobile packaging must ship or link libsodium.

## Alternatives considered

| Alt | Why not |
|-----|---------|
| Sodium backend inside libchssh | Contaminates OpenSSH interop path |
| Mutual TLS only | No multiplexed channels / agent subsystem model |
| Full Noise framework dep | Extra dependency; K16 provides Noise_IK-shaped binding with sodium |
