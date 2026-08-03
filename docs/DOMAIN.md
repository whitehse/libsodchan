# DOMAIN.md — libsodchan glossary

## Transport roles

| Term | Meaning |
|------|---------|
| **SERVER** | edgehost after TCP accept (raw) or after TLS unwrap |
| **CLIENT** | cpe_agent or mobile app initiating the connection |
| **Pin** | CLIENT-configured server Ed25519 public key; fail-closed by default |
| **Device key** | Long-lived Ed25519 keypair on CPE or mobile; private key never leaves device |
| **Enroll** | HTTPS `POST` of username/password + device pubkey; outside this library |
| **Bearer coexistence** | Mobile may keep HTTPS bearer for assets while sodchan carries control |

## Channels

Named multiplexed streams (SSH subsystem analogue). Product names:

| Name | Use |
|------|-----|
| `edge-telemetry` | Agent metrics/events |
| `edge-pg` | Postgres proxy / query path |
| `edge-ai` | AI control/results |
| `edge-control` | Config / cpe-config apply path |
| `edge-usp` | TR-369 USP MTP |
| `mobile-control` | Mobile app control plane |
| `shell` / `sftp` / `tun` / `tap` | Staff reverse access |

Images and SPA static assets are **not** channels; they stay on HTTPS.

## Ports (host)

| Port | Protocol |
|------|----------|
| 4334 | libchssh E7 NETCONF (unchanged) |
| 4335 | libchssh CPE (legacy dual-stack) |
| 4336 | libsodchan raw (CPE) |
| 4337 | TLS → libsodchan (mobile) |

## Crypto (suite v1)

- Identity: Ed25519 (`crypto_sign`, 32-byte pk / 64-byte sk)
- Ephemeral KX: X25519 `crypto_kx`
- Record AEAD: `crypto_secretstream` (XChaCha20-Poly1305)
- Server proof: Ed25519 over HELLO transcript (both ephemerals) before AUTH
