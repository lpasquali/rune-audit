# Case study: RUNE

The RUNE platform uses `rune-audit` as the **reference** deployment:

- Default `compliance-config.yaml` (when absent) targets the core RUNE GitHub repos.
- SR-Q catalog (`SR-Q-001`–`SR-Q-036`) tracks quantitative requirements documented in [rune-docs](https://github.com/lpasquali/rune-docs).
- CI in each repo calls shared workflows from `rune-ci`, including optional SR-2 verification against `main`.

External projects should start from `rune-audit init` and **not** rely on RUNE defaults — see [quickstart.md](quickstart.md).
