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
| 014 | Fixed libsodium crypto suite |
| 016 | Identity and session authentication |
| 017 | Normative wire format (suite V1) + vectors |

ADR 015 (channels / flow control) lands with PR-6.
