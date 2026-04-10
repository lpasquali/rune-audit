# CI integration

## GitHub Actions

```yaml
jobs:
  sr2-pack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
      - run: pip install rune-audit
      - run: rune-audit sr2 verify --pack slsa-l3 .
```

Pin versions in real workflows; the snippet is illustrative.

## GitLab CI

```yaml
sr2:
  image: python:3.14-slim
  script:
    - pip install rune-audit
    - rune-audit sr2 verify --pack nist-ssdf .
```

## Jenkins

Run the same shell commands inside a `sh` step with Python available.

## Strict mode

`rune-audit sr2 verify --strict` exits `2` if any `SR-Q-*` result is `not_implemented`. For pack-only runs, prefer checking JSON output and asserting on statuses your policy cares about.
