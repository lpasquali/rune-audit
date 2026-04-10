# Configuration reference

## `compliance-config.yaml` (v1)

Top-level fields:

| Field | Description |
| --- | --- |
| `version` | Schema version (integer, default `1`) |
| `project` | `name`, `github_org`, `repos` (list of `{name, type}`) |
| `compliance` | `standard`, `pack` (e.g. `builtin://slsa-l3`), optional `requirements_override` |
| `evidence` | Optional `gates`, `files`, `patterns` for future evidence wiring |

### RUNE defaults

If the file is **missing**, `rune-audit` uses RUNE ecosystem defaults (same repo list as legacy `rune-audit.yaml`).

### Overlay with `AuditConfig`

When `compliance-config.yaml` exists in the working directory, `AuditConfig.load()` uses `project.repos[].name` as the repo list for collectors that read `AuditConfig`.

## `.rune-audit-project.yaml`

Minimal multi-repo layout file used by `rune-audit sr2 config-validate`. Generated alongside `compliance-config.yaml` when you run `rune-audit init` without `--no-project-file`.

## Environment variables

Unchanged: `RUNE_AUDIT_GITHUB_TOKEN`, `RUNE_AUDIT_REPOS`, etc. See main README.
