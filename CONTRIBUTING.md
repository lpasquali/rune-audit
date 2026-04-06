# Contributing to rune-audit

Thank you for your interest in contributing to rune-audit. This document covers
the local development setup, coding standards, and PR process.

## Local Development Setup

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) or pip
- Git

### Setup

```bash
git clone https://github.com/lpasquali/rune-audit.git
cd rune-audit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest --cov=rune_audit --cov-report=term-missing
```

### Linting and Type Checking

```bash
ruff check rune_audit/ tests/
mypy rune_audit/
```

## Code Style

- **Formatter**: ruff (line length 120)
- **Linter**: ruff (select: E, F, W, I, N, UP, B, A, SIM, TCH)
- **Type checker**: mypy (strict mode)
- All code must pass `ruff check` and `mypy` with zero errors.

## Quality Gates

Every PR must pass the automated quality gates before merge:

- **Coverage floor**: 97% minimum on new code
- **Secret scanning**: gitleaks
- **License compliance**: Apache-2.0 verification
- **YAML validation**: All YAML files must parse cleanly
- **VEX validation**: All OpenVEX documents must be spec-compliant

## PR Process

1. Create a feature branch from `main`.
2. Write tests first (or alongside) --- 97% coverage floor is enforced.
3. Ensure `ruff check`, `mypy`, and `pytest` all pass locally.
4. Open a PR using the repository's PR template.
5. Reference the issue being resolved (`Closes #NNN`).
6. Check the appropriate DoD level in the PR body.
7. Provide evidence for all acceptance criteria.

## DCO / Signed-off-by

All commits must include a `Signed-off-by` line (Developer Certificate of
Origin). Use `git commit -s` to add it automatically.

## Full Coding Standards

For the complete coding standards covering all RUNE repositories, see
[rune-docs Coding Standards](https://github.com/lpasquali/rune-docs/blob/main/docs/context/CODING_STANDARDS.md).
