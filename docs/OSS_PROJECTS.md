# Using rune-audit on non-RUNE projects

rune-audit can verify generic OSS repositories against the same quantitative
security requirement catalog (IEC 62443-4-1 ML4 SR-2) used by RUNE.

1. Add a `.rune-audit-project.yaml` at your repo root (see `rune_audit.sr2.project_config.default_project_template()` or run `rune-audit sr2 init`).
2. Run `rune-audit sr2 verify --project .` from CI (see `rune-ci` workflow `sr2-compliance.yml`).
3. Inspectors start as stubs (`not_implemented`) until you register real checks via `InspectorRegistry`, the `@register_inspector` decorator (built-ins loaded when `default_registry()` runs), or a custom registry passed to `run_verification(..., registry=...)`.

Environment variables keep the `RUNE_AUDIT_*` prefix for historical compatibility.
