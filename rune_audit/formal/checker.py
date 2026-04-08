# SPDX-License-Identifier: Apache-2.0
"""TLA+ specification checker using TLC model checker."""

from __future__ import annotations

import logging
import re
import subprocess
import time
from pathlib import Path

from rune_audit.formal.models import CheckResult, SpecInfo

logger = logging.getLogger(__name__)

DEFAULT_SPECS_DIR = Path(__file__).resolve().parent.parent.parent / "specs"

_STATES_FOUND_RE = re.compile(r"(\d+)\s+states generated")
_DISTINCT_STATES_RE = re.compile(r"(\d+)\s+distinct states found")
_VIOLATION_RE = re.compile(r"Error:\s*(.+)")
_INVARIANT_VIOLATED_RE = re.compile(r"Invariant\s+(\S+)\s+is violated")


def _extract_description(spec_path: Path) -> str:
    """Extract a brief description from the spec file header comment."""
    try:
        text = spec_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r"\(\*\s*\n\s*\*\s*TLA\+\s+specification\s+(?:for\s+)?(.+?)\.", text)
    if match:
        return match.group(1).strip()
    match = re.search(r"\(\*\s*\n\s*\*\s*(.+?)\n", text)
    if match:
        return match.group(1).strip()
    return ""


def parse_tlc_output(stdout: str) -> tuple[bool, int, int, list[str]]:
    """Parse TLC model checker output."""
    violations: list[str] = []
    states_found = 0
    distinct_states = 0

    for match in _VIOLATION_RE.finditer(stdout):
        violations.append(match.group(1).strip())

    for match in _INVARIANT_VIOLATED_RE.finditer(stdout):
        violation_msg = f"Invariant {match.group(1)} is violated"
        if violation_msg not in violations:
            violations.append(violation_msg)

    states_match = _STATES_FOUND_RE.search(stdout)
    if states_match:
        states_found = int(states_match.group(1))

    distinct_match = _DISTINCT_STATES_RE.search(stdout)
    if distinct_match:
        distinct_states = int(distinct_match.group(1))

    passed = len(violations) == 0 and "Model checking completed" in stdout
    return passed, states_found, distinct_states, violations


class TLAChecker:
    """Run TLA+ specifications through the TLC model checker."""

    def __init__(
        self,
        specs_dir: Path | None = None,
        tlc_command: list[str] | None = None,
        timeout: int = 300,
    ) -> None:
        self.specs_dir = specs_dir or DEFAULT_SPECS_DIR
        self.tlc_command = tlc_command or ["java", "-jar", "tla2tools.jar"]
        self.timeout = timeout

    def check(self, spec_path: Path, config_path: Path | None = None) -> CheckResult:
        """Run TLC on a specification file."""
        spec_name = spec_path.stem
        cmd = list(self.tlc_command) + ["-deadlock"]
        if config_path is not None:
            cmd.extend(["-config", str(config_path)])
        cmd.append(str(spec_path))

        logger.info("Running TLC: %s", " ".join(cmd))
        start = time.monotonic()

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout, check=False,
            )
            duration = time.monotonic() - start
            stdout = result.stdout + result.stderr
            passed, states_found, distinct_states, violations = parse_tlc_output(stdout)
            return CheckResult(
                spec=spec_name, passed=passed,
                states_found=states_found, distinct_states=distinct_states,
                violations=violations, duration_seconds=round(duration, 3),
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            return CheckResult(
                spec=spec_name, passed=False,
                violations=[f"TLC timed out after {self.timeout}s"],
                duration_seconds=round(duration, 3),
            )
        except FileNotFoundError:
            duration = time.monotonic() - start
            return CheckResult(
                spec=spec_name, passed=False,
                violations=["TLC not found. Install tla2tools.jar or set tlc_command."],
                duration_seconds=round(duration, 3),
            )

    def list_specs(self) -> list[SpecInfo]:
        """List available TLA+ specifications."""
        if not self.specs_dir.is_dir():
            return []
        specs: list[SpecInfo] = []
        for tla_file in sorted(self.specs_dir.glob("*.tla")):
            description = _extract_description(tla_file)
            specs.append(SpecInfo(
                name=tla_file.stem, path=tla_file.resolve(), description=description,
            ))
        return specs
