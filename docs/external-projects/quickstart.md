# Quickstart (external OSS projects)

**Goal:** Run builtin compliance packs against *your* repository in about five minutes.

## 1. Install

```bash
pip install rune-audit
```

## 2. Bootstrap config

From your repo root:

```bash
rune-audit init -y --org YOUR_ORG --repos YOUR_REPO --no-project-file
```

This writes `compliance-config.yaml` (see [configuration.md](configuration.md)).

## 3. Run a pack

```bash
rune-audit sr2 verify --pack slsa-l3 .
rune-audit sr2 verify --pack owasp-asvs .
```

Builtin pack stems: `iec-62443-ml4`, `slsa-l3`, `cis-kubernetes`, `nist-ssdf`, `owasp-asvs`.

## 4. Full SR-Q catalog (RUNE-oriented)

```bash
rune-audit sr2 verify .
```

Inspectors for `SR-Q-*` are still mostly stubs unless your deployment wires real checks (see [inspector-library.md](inspector-library.md)).

## References

- Tracking: [lpasquali/rune-docs#227](https://github.com/lpasquali/rune-docs/issues/227) – [lpasquali/rune-docs#232](https://github.com/lpasquali/rune-docs/issues/232)
