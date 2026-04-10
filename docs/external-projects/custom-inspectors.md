# Custom inspectors

```python
from pathlib import Path

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import InspectResult, InspectStatus, Priority, RequirementSpec
from rune_audit.sr2.registry import inspector


@inspector("MY-REQ-001")
def my_check(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    marker = ctx.root / "MY_COMPLIANCE_STAMP"
    if marker.is_file():
        return InspectResult(requirement_id=spec.id, status=InspectStatus.PASS, detail="stamp present")
    return InspectResult(requirement_id=spec.id, status=InspectStatus.FAIL, detail="missing stamp")


def exercise() -> None:
    ctx = InspectContext(root=Path("."))
    spec = RequirementSpec(id="MY-REQ-001", title="demo", priority=Priority.P2)
    print(my_check(ctx, spec))
```

Register **before** running verification so the default registry picks up your function.

For packaging, expose a module entry point and import it from your `compliance-config` bootstrap code (pattern still evolving — see epic [#208](https://github.com/lpasquali/rune-docs/issues/208)).
