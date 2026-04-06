# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in rune-audit, please report it
responsibly.

**Contact**: [luca@bucaniere.us](mailto:luca@bucaniere.us)

**Acknowledgment SLA**: You will receive an acknowledgment within **48 hours**
of your report.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (if known)
- Suggested fix (if any)

**Do not** open a public GitHub issue for security vulnerabilities.

## Supported Versions

| Version        | Supported |
|----------------|-----------|
| 0.0.0a0 (dev)  | Yes       |

## Merge Protection Policy

All pull requests are subject to automated quality gates. Dependencies with a
CVSS score above **8.8** block the merge gate. No exceptions.

Vulnerabilities below the threshold may be risk-accepted only when no upstream
fix exists. All risk-accepted CVEs are tracked in the
[VEX Register](https://github.com/lpasquali/rune-docs/blob/main/docs/delivery/VEX.md).

## Security Scanning

Every pull request automatically runs:

- **gitleaks** for hardcoded credential detection (IEC 62443 4-1 ML4 SM-8)
- **pip-audit** / **grype** for dependency vulnerability scanning
- **SLSA Level 3** build provenance via GitHub Attestations

## Full Security Policy

For the complete security policy covering all RUNE repositories, see
[rune-docs SECRETS.md](https://github.com/lpasquali/rune-docs/blob/main/docs/operations/SECRETS.md).
