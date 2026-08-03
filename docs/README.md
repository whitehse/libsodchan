# libsodchan documentation

| Doc | Purpose |
|-----|---------|
| [../AGENTS.md](../AGENTS.md) | Agent entry: commands, rules, status |
| [../ARCHITECTURE.md](../ARCHITECTURE.md) | Module map, invariants, ports |
| [DOMAIN.md](DOMAIN.md) | Glossary (channels, enroll, pin) |
| [decisions/](decisions/) | Architecture Decision Records |
| `~/docs/libsodchan-design.md` | Full design (wire, enroll, PR plan) |

## ADR index

| ADR | Title |
|-----|-------|
| 001 | Agent-ready documentation |
| 002 | Event-loop compatibility |
| 003 | Testing, fuzzing, valgrind |
| 004 | Dialectic client/server testing |
| 006 | Core library as plumbing |
| 009 | Consistent protocol interfaces |

Sodchan-specific ADRs (014–017) land with later PRs (crypto suite, channels, identity, wire format).
