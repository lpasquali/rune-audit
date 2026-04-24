# SPDX-License-Identifier: Apache-2.0
"""API server security implementation inspectors (EPIC #211)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.models import InspectResult

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import fail, na, ok, read_text_safe
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect_api_server(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    api_server = root / "rune" / "rune_bench" / "api_server.py"
    if not api_server.is_file():
        # Maybe we are in the 'rune' repo itself
        api_server = root / "rune_bench" / "api_server.py"

    if not api_server.is_file():
        return na(spec, "api_server.py not found")

    text = read_text_safe(api_server)

    if spec.id == "SR-Q-001":
        if "len(secret) < 32" in text and "minimum length is 32 characters" in text:
            return ok(spec, "API token minimum length 32 enforced (entropy check)")
        return fail(spec, "API token length check not found")

    if spec.id == "SR-Q-002":
        if "len(history) >= 10" in text and "_auth_failures" in text:
            return ok(spec, "auth failure rate limit 10 enforced")
        return fail(spec, "auth failure rate limit 10 not found in api_server.py")

    if spec.id == "SR-Q-007":
        # This one is in postgres.py
        postgres_adapter = root / "rune" / "rune_bench" / "storage" / "postgres.py"
        if not postgres_adapter.is_file():
            postgres_adapter = root / "rune_bench" / "storage" / "postgres.py"

        if not postgres_adapter.is_file():
            return na(spec, "postgres.py not found")

        pg_text = read_text_safe(postgres_adapter)
        if 'get("RUNE_PG_POOL_MAX", "10")' in pg_text:
            return ok(spec, "PostgreSQL pool max size 10 enforced")
        return fail(spec, "PostgreSQL pool max size 10 not found in postgres.py")

    if spec.id == "SR-Q-004":
        if "self.rfile.read(length)" in text and "_MAX_BODY_SIZE" in text:
            return ok(spec, "request body size limit enforced")
        return fail(spec, "body size limit not found in api_server.py")

    if spec.id == "SR-Q-005":
        if "len(history) >= 100" in text and "RequestRateLimited" in text:
            return ok(spec, "rate limit 100 enforced")
        return fail(spec, "rate limit 100 not found in api_server.py")

    if spec.id == "SR-Q-008":
        if "_HTTP_REQUEST_SOCKET_TIMEOUT_S = 30.0" in text:
            return ok(spec, "HTTP server timeout 30s enforced")
        return fail(spec, "HTTP server timeout 30s not found")

    if spec.id == "SR-Q-016":
        if "len(secret) < 32" in text and "minimum length is 32 characters" in text:
            return ok(spec, "API token minimum length 32 enforced")
        return fail(spec, "token length enforcement not found")

    if spec.id == "SR-Q-024":
        if "class JsonFormatter(logging.Formatter):" in text:
            return ok(spec, "Structured JSON logging implemented")
        return fail(spec, "JsonFormatter not found")

    return na(spec, "unsupported SR-Q ID for api_server inspector")


def _inspect_api_contracts(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    contracts = root / "rune" / "rune_bench" / "api_contracts.py"
    if not contracts.is_file():
        contracts = root / "rune_bench" / "api_contracts.py"

    if not contracts.is_file():
        return na(spec, "api_contracts.py not found")

    text = read_text_safe(contracts)
    if "def __post_init__(self) -> None:" in text and "_check_max_str" in text:
        return ok(spec, "string length limits enforced via __post_init__")
    return fail(spec, "__post_init__ validation not found in api_contracts.py")


def _inspect_driver_timeouts(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    http_driver = root / "rune" / "rune_bench" / "drivers" / "http.py"
    if not http_driver.is_file():
        http_driver = root / "rune_bench" / "drivers" / "http.py"

    if not http_driver.is_file():
        return na(spec, "drivers/http.py not found")

    text = read_text_safe(http_driver)
    if "driver_invocation_timeout_seconds()" in text:
        return ok(spec, "driver invocation timeout standardized")
    return fail(spec, "driver_invocation_timeout_seconds() not used in http.py")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.api_server_security", _inspect_api_server)
    reg.register("stdlib.api_contracts_security", _inspect_api_contracts)
    reg.register("stdlib.driver_timeouts", _inspect_driver_timeouts)

    # Map SR-Q IDs
    reg.register("SR-Q-001", _inspect_api_server)
    reg.register("SR-Q-002", _inspect_api_server)
    reg.register("SR-Q-004", _inspect_api_server)
    reg.register("SR-Q-005", _inspect_api_server)
    reg.register("SR-Q-007", _inspect_api_server)
    reg.register("SR-Q-008", _inspect_api_server)
    reg.register("SR-Q-011", _inspect_driver_timeouts)
    reg.register("SR-Q-016", _inspect_api_server)
    reg.register("SR-Q-024", _inspect_api_server)
    reg.register("SR-Q-035", _inspect_api_contracts)
