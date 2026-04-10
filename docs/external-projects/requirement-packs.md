# Requirement pack authoring

## Builtin packs

Shipped as YAML under `rune_audit/sr2/builtin_packs/` (package data in the wheel):

- `iec-62443-ml4.yaml`
- `slsa-l3.yaml`
- `cis-kubernetes.yaml`
- `nist-ssdf.yaml`
- `owasp-asvs.yaml`

Load in Python:

```python
from rune_audit.sr2.packs import load_builtin_pack

doc = load_builtin_pack("owasp-asvs")
print(doc.pack.name, [r.id for r in doc.requirements])
```

## Schema (informal)

```yaml
pack:
  name: "My pack"
  standard: "custom"
  version: "1.0"
requirements:
  - id: "REQ-1"
    title: "Example"
    category: "General"
    priority: "P2"
    inspector: "stdlib.license_compliance"
```

- `inspector: builtin://stub` → stub inspector (`not_implemented`).
- `inspector: stdlib.*` → standard library inspector.

Run via CLI:

```bash
rune-audit sr2 verify --pack owasp-asvs .
```
