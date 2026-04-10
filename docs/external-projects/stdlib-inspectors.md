# Standard library inspectors (`stdlib.*`)

Implementations live under `rune_audit/sr2/inspectors/stdlib/` (rune-docs#230). They are **heuristic** checks over the repository tree and GitHub Actions workflows, not cryptographic or cloud proof. Like the rest of `rune_audit`, they are included in the project coverage gate (97%).

## Shared behavior

- **PASS / FAIL / NOT_APPLICABLE**: If the expected technology or artifact is absent, inspectors return `not_applicable` with a short reason (except where a missing policy file is treated as N/A, e.g. Dependabot).
- **Thresholds**: Pack rows may include a `threshold` mapping (see [requirement packs](requirement-packs.md)). It is passed through on `RequirementSpec.threshold` and read per inspector (see below).

---

## `stdlib.python_coverage`

- **Intent**: Python project appears to configure coverage.
- **NOT_APPLICABLE**: No `pyproject.toml` / `setup.py` / `setup.cfg`.
- **PASS**: `.coveragerc` exists or `pyproject.toml` mentions `coverage` (case-insensitive).
- **Thresholds**: none.

## `stdlib.go_coverage`

- **Intent**: Go module with tests present.
- **NOT_APPLICABLE**: No `go.mod`, or no `*_test.go` files.
- **PASS**: `go.mod` and at least one `*_test.go`.
- **Thresholds**: none.

## `stdlib.helm_security_context`

- **Intent**: Helm-style YAML under `charts/` or `*/templates/` mentions `securityContext`.
- **NOT_APPLICABLE**: No matching YAML with `securityContext`.
- **PASS**: First matching file path is noted in the detail.
- **Thresholds**: none.

## `stdlib.dockerfile_security`

- **Intent**: Dockerfiles declare a non-root `USER`.
- **NOT_APPLICABLE**: No `Dockerfile` at repo root or under `**/Dockerfile` (glob).
- **PASS**: `USER` directive found in one of the first N Dockerfiles scanned.
- **FAIL**: Scanned Dockerfiles lack `USER`.
- **Thresholds**:
  - `max_dockerfiles_to_scan` (int, default `5`): cap on files examined.

## `stdlib.github_actions_pinning`

- **Intent**: GitHub Actions `uses:` references are pinned to a commit SHA or a `v`-prefixed version tag.
- **NOT_APPLICABLE**: No `.github/workflows`, or no `uses:` steps.
- **PASS**: Every non-template `uses:` line matches the pin heuristic.
- **FAIL**: At least one unpinned reference.
- **Thresholds**: none.

## `stdlib.dependabot_config`

- **Intent**: Dependabot config file exists.
- **NOT_APPLICABLE**: No `.github/dependabot.yml` or `.github/dependabot.yaml`.
- **PASS**: Either file exists.
- **Thresholds**: none.

## `stdlib.sbom_completeness`

- **Intent**: SBOM-like JSON artifacts are present.
- **NOT_APPLICABLE**: No matching globs.
- **PASS**: Matches `**/sbom*.json`, `**/*cyclonedx*.json`, or `**/bom.json`.
- **Thresholds**: none.

## `stdlib.slsa_verification`

- **Intent**: Workflows mention SLSA / provenance / attestation keywords.
- **NOT_APPLICABLE**: No workflows or no keyword hits.
- **PASS**: `slsa`, `provenance`, or `attest` found (case-insensitive).
- **Thresholds**: none.

## `stdlib.secret_scanning`

- **Intent**: CI references secret scanning tools.
- **NOT_APPLICABLE**: No workflows or no matching hints.
- **PASS**: References to GitGuardian, TruffleHog, Gitleaks, or text containing both `secret` and `scan`.
- **Thresholds**: none.

## `stdlib.sast_coverage`

- **Intent**: CI references static analysis.
- **NOT_APPLICABLE**: No workflows or no SAST hints.
- **PASS**: `codeql`, `semgrep`, `bandit`, or `sast` in workflow text.
- **Thresholds**: none.

## `stdlib.license_compliance`

- **Intent**: A license file exists at the repository root with non-trivial size.
- **FAIL**: No `LICENSE`, `LICENSE.txt`, `LICENSE.md`, or `COPYING`, or all are smaller than the minimum size.
- **PASS**: First qualifying file found.
- **Thresholds**:
  - `min_license_bytes` (int, default `21`): minimum file size in bytes (inclusive). Values below `1` are clamped to `1`.

## `stdlib.vulnerability_scanning`

- **Intent**: CI references a vulnerability scanner.
- **NOT_APPLICABLE**: No workflows or no tool hints.
- **PASS**: `grype`, `trivy`, `snyk`, or `osv` in workflow text.
- **Thresholds**: none.

## `stdlib.container_signing`

- **Intent**: CI references container signing.
- **NOT_APPLICABLE**: No workflows or no signing hints.
- **PASS**: `cosign` or `sigstore` in workflow text.
- **Thresholds**: none.

## `stdlib.network_policy_presence`

- **Intent**: A Kubernetes manifest declares a `NetworkPolicy`.
- **NOT_APPLICABLE**: No YAML/YAML with `kind: NetworkPolicy`.
- **PASS**: First matching file path in detail.
- **Thresholds**: none.

## `stdlib.rbac_least_privilege`

- **Intent**: RBAC `Role` manifests exist (shallow structural check).
- **NOT_APPLICABLE**: No manifest with `kind:` containing `Role` alongside `apiVersion:`.
- **PASS**: First matching file path in detail.
- **Thresholds**: none.
