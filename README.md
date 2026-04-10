# rune-audit

Auditing and compliance tracking for the
[RUNE](https://github.com/lpasquali/rune) platform.

rune-audit collects, verifies, and reports on security and compliance evidence
across the RUNE ecosystem. It verifies SLSA Level 3 build provenance, manages
VEX (Vulnerability Exploitability eXchange) documents, and generates IEC 62443
evidence matrices.

## Architecture

```
rune-audit
  collect      Gather SBOMs, CVE scans, VEX documents from all repos
  vex          Manage and validate OpenVEX documents
  compliance   IEC 62443 evidence matrix and gap analysis
  slsa         SLSA Level 3 provenance verification
  report       Full, summary, and delta audit reports
  config       Display current configuration
```

**Evidence sources**: GitHub Attestations API, SBOM files, CVE scan results,
OpenVEX documents.

**Outputs**: Rich terminal tables, Markdown reports, JSON exports.

## Installation

```bash
pip install rune-audit
```

Or for development:

```bash
git clone https://github.com/lpasquali/rune-audit.git
cd rune-audit
pip install -e ".[dev]"
```

## Quick Start

```bash
# Verify SLSA L3 provenance for a single repo
rune-audit slsa verify rune --tag v0.0.0a2

# Verify SLSA across all ecosystem repos
rune-audit slsa verify-all --tag v0.0.0a2

# Show IEC 62443 evidence matrix
rune-audit compliance matrix

# Show compliance gaps
rune-audit compliance gaps

# Validate VEX documents
rune-audit vex validate

# List VEX statements
rune-audit vex list

# Generate full audit report
rune-audit report full

# Show configuration
rune-audit config show
```

## External OSS projects (compliance-config & packs)

For non-RUNE repositories, use `compliance-config.yaml` and builtin packs (`rune-audit init`, `rune-audit sr2 verify --pack …`). See **[docs/external-projects/quickstart.md](docs/external-projects/quickstart.md)** (covers [rune-docs#227](https://github.com/lpasquali/rune-docs/issues/227)–[#232](https://github.com/lpasquali/rune-docs/issues/232)).

## Supported Evidence Types

| Type | Description | Source |
|------|-------------|--------|
| SLSA Provenance | Build attestation verification | GitHub Attestations API |
| SBOM | Software Bill of Materials | CycloneDX / SPDX |
| CVE Scans | Vulnerability scan results | pip-audit, grype |
| VEX | Vulnerability Exploitability eXchange | OpenVEX documents |
| License | License compliance status | SPDX headers, LICENSE files |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `RUNE_AUDIT_GITHUB_TOKEN` | GitHub API token (fallback: `gh auth token`) | -- |
| `RUNE_AUDIT_REPOS` | Comma-separated repo list | All 6 RUNE repos |
| `RUNE_AUDIT_OUTPUT_DIR` | Report output directory | `./audit-output/` |

Optional YAML config file: `rune-audit.yaml`

## Compliance Context

- **IEC 62443-4-1 ML4**: This repository aligns with IEC 62443-4-1 Maturity
  Level 4 secure development requirements.
- **SLSA Level 3**: Build provenance is verified against all five SLSA L3
  requirements (provenance exists, signed, trusted builder, version-controlled
  source, isolated build).

## Documentation

Full documentation is consolidated in
[rune-docs](https://github.com/lpasquali/rune-docs).

## License

Apache License 2.0. See [LICENSE](LICENSE).
