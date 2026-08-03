# TODO — libsodchan

Major progress tracking (ADR 013 lineage from siblings).

## Done

- [x] PR-1: Scaffold — CMake, AGENTS, plumbing ADRs, public API, create/destroy smoke
- [x] PR-2: sodium keygen (64-byte sk), SCSK seeds, fingerprints, FindSodium, ADR 014
- [x] PR-3: ADR 017 wire format + hex vectors + encode/decode
- [x] PR-4: HELLO + server id_sig + KX + secretstream headers + MITM/dialectic
- [x] PR-5: AUTH_DEVICE + auth_decide + AUTH_OK/FAIL → READY
- [x] PR-6: Multiplexed channels + flow control
- [x] PR-7: Fuzz harness + corpus + valgrind/ASan scripts

## In progress / next

- [ ] PR-8+: edgehost / cpe_agent / mobile (see design PR plan)

## Open ops (not library)

- AUTH_FAIL tarpit duration (host, 200–1000 ms default)
- Postgres device store vs file (prod track)
