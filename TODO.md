# TODO — libsodchan

Major progress tracking (ADR 013 lineage from siblings).

## Done

- [x] PR-1: Scaffold — CMake, AGENTS, plumbing ADRs, public API, create/destroy smoke
- [x] PR-2: sodium keygen (64-byte sk), SCSK seeds, fingerprints, FindSodium, ADR 014
- [x] PR-3: ADR 017 wire format + hex vectors + encode/decode

## In progress / next

- [ ] PR-4: HELLO + mandatory server sig + KX + secretstream headers + MITM test
- [ ] PR-5: AUTH_DEVICE + auth_decide
- [ ] PR-6: Multiplexed channels + flow control
- [ ] PR-7: Fuzz + valgrind
- [ ] PR-8+: edgehost / cpe_agent / mobile (see design PR plan)

## Open ops (not library)

- AUTH_FAIL tarpit duration (host, 200–1000 ms default)
- Postgres device store vs file (prod track)
