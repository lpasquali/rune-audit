# RUNE-Audit Test Suite

Tests for compliance auditing, SLSA verification, and quantitative requirement inspectors.

## Directory Structure

- **`test_cli/`**: Tests for the `rune-audit` CLI tool and subcommands.
- **`test_collectors/`**: Evidence collection logic (GitHub, Operator, etc.).
- **`test_formal/`**: TLA+ formal verification checkers.
- **`test_models/`**: Pydantic data models for SBOM, SLSA, and VEX.
- **`test_rekor/`** / **`test_sigstore/`**: Supply-chain security integrations.
- **`test_validators/`** / **`test_verifiers/`**: ML4 compliance and SR-2 requirement verification logic.

## Running Tests

Tests are run using `pytest`:

```bash
# Run all audit tests
python -m pytest tests/

# Run a specific category
python -m pytest tests/test_collectors/
```
