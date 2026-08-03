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

**Current status (v0.1 / PR-1 scaffold)**:
- Public API in `include/sodchan.h` (design-aligned).
- `sodchan_create` / `destroy` / `reset` with pin + lab_mode gates.
- Plumbing stubs: feed/get/next_event/channel/auth return empty or `SODCHAN_ERR_STATE`.
- Keygen stubs return `SODCHAN_ERR_STATE` until PR-2 (sodium).
- Smoke test covers create policy and lifecycle.

**Next PRs** (see design PR plan):
- PR-2: sodium keygen, fingerprints, FindSodium
- PR-3: wire ADR 017 + hex vectors
- PR-4+: handshake, auth, channels, host/agent/mobile

**Dependencies**:
- **libsodium** — required from PR-2 onward (not linked in PR-1 scaffold).
- No OpenSSH / libchssh dependency.

**Interface direction**:
- `sodchan_create(role, &cfg)` with `SODCHAN_ROLE_SERVER` / `SODCHAN_ROLE_CLIENT`
- `sodchan_feed_input` / `sodchan_get_output` / `sodchan_next_event`
- `sodchan_auth_decide` (server policy hook after AUTH_DEVICE)
- `sodchan_channel_open` / `send` / `window_avail` after READY
