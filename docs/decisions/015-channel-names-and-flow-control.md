# ADR 015: Channel Names and Flow Control

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

After AUTH → READY, apps need multiplexed named streams (telemetry, control, USP, mobile-control) with backpressure similar to SSH channels, without embedding product payload codecs in libsodchan.

## Decision

### Names

- Channel names are UTF-8 strings ≤63 bytes (product subsystem strings).
- Default server allowlist (when `allowed_channels` is NULL):

  `edge-telemetry,edge-pg,edge-ai,edge-control,edge-usp,shell,sftp,exec,tun,tap,mobile-control,mobile-sync,mobile-audit,mobile-notify`

- Hosts should pass a tighter list in production.
- Disallowed peer OPEN → automatic `CHANNEL_OPEN_FAIL` (`ADMIN_PROHIBITED`); no host event.

### IDs

- Each side allocates independent **local** ids (starting at 0).
- OPEN carries opener’s local id as `sender_channel`.
- CONFIRM binds dual ids; API users always pass **local** id to send/close/window.

### Flow control

- Per-channel `send_window` (credit toward peer) and `recv_window` (remaining peer credit toward us).
- OPEN/CONFIRM advertise `init_window` and `max_packet` (defaults 256 KiB / 64 KiB).
- `sodchan_channel_send`: all-or-nothing; `SODCHAN_ERR_WINDOW` if peer credit insufficient; `SODCHAN_ERR_FULL` if output buffer full.
- Hosts call `sodchan_channel_window_adjust` after consuming DATA to restore credit.
- Incoming WINDOW → `SODCHAN_EVENT_CHANNEL_WINDOW` with `window_avail`.

### Lifecycle events

`CHANNEL_OPEN` → host `channel_accept` → `CHANNEL_OPENED` / `CHANNEL_OPEN_FAIL` / `CHANNEL_DATA` / `CHANNEL_EOF` / `CHANNEL_CLOSE`.

PING auto-replies with PONG and emits `EVENT_PING`.

## Consequences

- Payload framing (NDJSON, USP, PG, HTTP) stays host-owned on channel bytes.
- PR-6 tests cover open/data/window and allowlist rejection.
