# AGENTS.md — libsodchan

**Project identity**: Pure C state-machine **libsodium multiplexed channel** transport. System-call free, callback free. SSH-like session model (HELLO, KX with server identity proof, device pubkey auth, named channels, flow control) for **CPE agent call-home** and **mobile control plane**. Host owns sockets, TLS termination (mobile :4337), and auth policy. Does **not** replace libchssh for E7/NETCONF Call Home.

**Key commands** (run from repo root):
- `cmake -B build -S . && cmake --build build` — configure and build static library + tests
- `ctest --test-dir build --output-on-failure` — run verification tests

**Documentation map**:
- AGENTS.md (this file) — start here
- ARCHITECTURE.md — module boundaries, invariants, ports
- docs/README.md — documentation index
- docs/DOMAIN.md — domain glossary (channels, enroll, pin)
- docs/decisions/ — ADRs (common sibling decisions + sodchan-specific)
- Design doc: `~/docs/libsodchan-design.md` (full protocol + PR plan)

**Operating rules**:
- Never introduce system calls, callbacks, or hidden I/O in the core library.
- Progress is pull-driven: `sodchan_feed_input` / `sodchan_next_event` / `sodchan_get_output`.
- Fail-closed CLIENT pin: `accept_any_server_pk=0` requires `server_id_pk` at create.
- `lab_mode` only if compiled with `SODCHAN_ALLOW_LAB_CLEARTEXT` (default OFF).
- Strict warnings: `-Wall -Wextra -Wpedantic -Werror`.
- Prefer small patches; update ADRs when architecture changes.
- Wire format ADR 017 + hex vectors **before** handshake merge (PR-3 before PR-4).

**Definition of done**:
- Builds clean; `ctest` green.
- Docs accurate.
- No new syscalls/callbacks.
- Dialectic tests cover READY → channel data when implemented.

**Current status (v0.6 / PR-6 channels)**:
- Full session: HELLO → KX → AUTH → READY → **named channels**.
- `channel_open` / `accept` / `send` / `window_adjust` / `eof` / `close`.
- Flow control: per-channel windows; `ERR_WINDOW` / `ERR_FULL`; allowlist filter.
- Events: CHANNEL_OPEN/OPENED/OPEN_FAIL/DATA/WINDOW/EOF/CLOSE, PING.
- Tests: smoke, crypto, wire, dialectic, mitm, auth, **channels**.

**Next PRs** (see design PR plan):
- PR-7: fuzz + valgrind
- PR-8+: edgehost / cpe_agent / mobile

**Dependencies**:
- **libsodium** (required). Install `libsodium-dev` or set `SODIUM_ROOT` / extract headers under `third_party/sodium-prefix/usr`.
- No OpenSSH / libchssh dependency.

**Interface direction**:
- `sodchan_create(role, &cfg)` with `SODCHAN_ROLE_SERVER` / `SODCHAN_ROLE_CLIENT`
- `sodchan_feed_input` / `sodchan_get_output` / `sodchan_next_event`
- `sodchan_auth_decide` (server policy hook after AUTH_DEVICE)
- `sodchan_channel_open` / `send` / `window_avail` after READY
