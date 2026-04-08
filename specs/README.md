# TLA+ Formal Verification Specs

TLA+ specifications verifying key audit invariants of the RUNE audit system.

## Prerequisites

```bash
wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
```

## Specifications

| Spec | Verifies |
|---|---|
| `AuditChain.tla` | Evidence chain: signing order, no gaps, immutability |
| `ComplianceMatrix.tla` | IEC 62443 compliance: monotonic status, evidence mapping |
| `GateAggregation.tla` | Cross-repo gates: PASS requires all, FAIL propagates |

## Running

```bash
rune-audit formal list
rune-audit formal check AuditChain
java -jar tla2tools.jar -deadlock specs/AuditChain.tla
```
