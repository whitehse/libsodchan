# libsodchan

Pure C, system-call-free, callback-free **libsodium multiplexed channel** transport for ECOEC CPE agent call-home and mobile control plane.

Resembles SSH (session, named channels, flow control) without OpenSSH wire compatibility. **Does not** replace [libchssh](../libchssh) for NETCONF Call Home (E7).

## Build

```bash
cmake -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure
```

## Quick API

```c
#include "sodchan.h"

sodchan_config_t cfg;
memset(&cfg, 0, sizeof(cfg));
cfg.server_id_pk = server_pk; /* 32 bytes */
cfg.server_id_sk = server_sk; /* 64 bytes sodium format */

sodchan_ctx_t *s = sodchan_create(SODCHAN_ROLE_SERVER, &cfg);
/* host loop: feed_input / get_output / next_event */
sodchan_destroy(s);
```

See `AGENTS.md` and `docs/libsodchan-design.md` (workspace design doc).

## Status

**v0.1 (PR-1 scaffold)** — API surface, create/destroy policy, smoke test. Crypto and wire protocol follow in PR-2+.

## License

MIT
