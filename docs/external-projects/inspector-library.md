# Inspector library

## Builtin `stdlib.*` inspectors

These ship under `rune_audit/sr2/inspectors/stdlib/` (per rune-docs#230) and register on the default `InspectorRegistry`. They are **heuristic** (filesystem / workflow text checks), not full compliance proof.

Per-inspector behavior, `NOT_APPLICABLE` rules, and **threshold** keys are documented in [stdlib-inspectors.md](stdlib-inspectors.md).

| Id | Intent |
| --- | --- |
| `stdlib.python_coverage` | Python tree + coverage config hints |
| `stdlib.go_coverage` | `go.mod` + `*_test.go` |
| `stdlib.helm_security_context` | Helm templates under `charts/` with `securityContext` |
| `stdlib.dockerfile_security` | `Dockerfile` `USER` directive |
| `stdlib.github_actions_pinning` | Pinned `uses:` refs in workflows |
| `stdlib.dependabot_config` | `.github/dependabot.yml` |
| `stdlib.sbom_completeness` | SBOM-like JSON filenames |
| `stdlib.slsa_verification` | Workflow keywords (slsa / provenance / attest) |
| `stdlib.secret_scanning` | Secret-scanning tools in workflows |
| `stdlib.sast_coverage` | SAST tools in workflows |
| `stdlib.license_compliance` | Root `LICENSE` file |
| `stdlib.vulnerability_scanning` | Grype/Trivy/Snyk/OSV in workflows |
| `stdlib.container_signing` | cosign/sigstore in workflows |
| `stdlib.network_policy_presence` | `NetworkPolicy` manifests |
| `stdlib.rbac_least_privilege` | RBAC `Role` manifests |

Statuses include `not_applicable` when the technology is absent.

## Custom inspectors

Use `InspectorRegistry.register` or the `@inspector` decorator from `rune_audit.sr2.registry` (see [custom-inspectors.md](custom-inspectors.md)).

## SR-Q catalog

`SR-Q-001` … `SR-Q-036` use the registry; unregistered ids fall back to `stub_inspector` (`not_implemented`).
