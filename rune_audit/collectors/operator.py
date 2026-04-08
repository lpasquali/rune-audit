# SPDX-License-Identifier: Apache-2.0
"""Collector for rune-operator RuneBenchmark CRs.

Collects run records and audit trails from Kubernetes RuneBenchmark
custom resources created by the rune-operator.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime
from typing import Any

from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.operator import AuditEvent, AuditTrail, RunRecord

logger = logging.getLogger(__name__)

DEFAULT_CRD_GROUP = "bench.rune.ai"
DEFAULT_CRD_VERSION = "v1alpha1"
DEFAULT_CRD_RESOURCE = "runebenchmarks"


def _run_kubectl(args: list[str], timeout: int = 30) -> str:
    """Run a kubectl command and return stdout."""
    cmd = ["kubectl"] + args
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=True,
    )
    return result.stdout


def _parse_run_record(item: dict[str, Any]) -> RunRecord:
    """Parse a RuneBenchmark CR into a RunRecord."""
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})

    created_at_str = metadata.get("creationTimestamp", "")
    created_at = (
        datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        if created_at_str
        else datetime.now()
    )

    completed_at = None
    completed_str = status.get("completedAt", "")
    if completed_str:
        completed_at = datetime.fromisoformat(completed_str.replace("Z", "+00:00"))

    return RunRecord(
        name=metadata.get("name", ""),
        namespace=metadata.get("namespace", "default"),
        status=status.get("phase", "Unknown"),
        agent=spec.get("agent", ""),
        model=spec.get("model", ""),
        backend_type=spec.get("backendType", "ollama"),
        result=status.get("result"),
        cost_estimation=spec.get("costEstimation"),
        created_at=created_at,
        completed_at=completed_at,
    )


def _parse_events(events_data: list[dict[str, Any]], run_name: str) -> list[AuditEvent]:
    """Parse Kubernetes events into AuditEvents."""
    audit_events: list[AuditEvent] = []
    for event in events_data:
        involved = event.get("involvedObject", {})
        if involved.get("name") != run_name:
            continue
        timestamp_str = event.get("lastTimestamp", "") or event.get("firstTimestamp", "")
        if not timestamp_str:
            continue
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        audit_events.append(AuditEvent(
            timestamp=timestamp,
            event_type=event.get("reason", "Unknown"),
            message=event.get("message", ""),
            details={"type": event.get("type", ""), "count": event.get("count", 1)},
        ))
    return sorted(audit_events, key=lambda e: e.timestamp)


class OperatorCollector:
    """Collect audit data from RuneBenchmark custom resources."""

    def __init__(self, kubectl_fn: Any = None, timeout: int = 30) -> None:
        """Initialize collector.

        Args:
            kubectl_fn: Optional callable replacing _run_kubectl for testing.
            timeout: Timeout for kubectl commands.
        """
        self._kubectl = kubectl_fn or _run_kubectl
        self._timeout = timeout

    def collect_run_records(self, namespace: str | None = None) -> list[RunRecord]:
        """List RuneBenchmark CRs and extract run records.

        Args:
            namespace: Kubernetes namespace (None = all namespaces).

        Returns:
            List of RunRecord parsed from CRs.
        """
        args = ["get", f"{DEFAULT_CRD_RESOURCE}.{DEFAULT_CRD_GROUP}", "-o", "json"]
        if namespace:
            args.extend(["-n", namespace])
        else:
            args.append("--all-namespaces")

        try:
            raw = self._kubectl(args, timeout=self._timeout)
            data = json.loads(raw)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("Failed to collect run records: %s", exc)
            return []

        items = data.get("items", [])
        return [_parse_run_record(item) for item in items]

    def collect_audit_trail(self, run_name: str, namespace: str = "default") -> AuditTrail:
        """Collect full audit trail for a specific RuneBenchmark run.

        Args:
            run_name: Name of the RuneBenchmark resource.
            namespace: Kubernetes namespace.

        Returns:
            AuditTrail with events and run records.
        """
        # Get the specific CR
        args = ["get", f"{DEFAULT_CRD_RESOURCE}.{DEFAULT_CRD_GROUP}", run_name,
                "-n", namespace, "-o", "json"]
        records: list[RunRecord] = []
        try:
            raw = self._kubectl(args, timeout=self._timeout)
            item = json.loads(raw)
            records.append(_parse_run_record(item))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("Failed to get CR %s: %s", run_name, exc)

        # Get events for this resource
        events_args = ["get", "events", "-n", namespace, "-o", "json"]
        events: list[AuditEvent] = []
        try:
            raw = self._kubectl(events_args, timeout=self._timeout)
            events_data = json.loads(raw)
            events = _parse_events(events_data.get("items", []), run_name)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("Failed to get events for %s: %s", run_name, exc)

        return AuditTrail(run_name=run_name, events=events, records=records)

    def enrich_evidence(self, bundle: EvidenceBundle, records: list[RunRecord]) -> EvidenceBundle:
        """Add operator run data to an evidence bundle.

        This enriches the bundle's metadata with operator run records,
        adding them as additional gate results.

        Args:
            bundle: Existing evidence bundle to enrich.
            records: Run records to add.

        Returns:
            The enriched EvidenceBundle (mutated in place and returned).
        """
        from rune_audit.models.gate import GateResult, GateStatus

        for record in records:
            status_map = {
                "Complete": GateStatus.PASS,
                "Failed": GateStatus.FAIL,
                "Pending": GateStatus.PENDING,
                "Running": GateStatus.PENDING,
            }
            gate_status = status_map.get(record.status, GateStatus.SKIP)
            gate = GateResult(
                gate_name=f"operator/{record.name}",
                status=gate_status,
                source_repo=f"{record.namespace}/{record.name}",
                conclusion=record.status,
                timestamp=record.completed_at or record.created_at,
            )
            bundle.gate_results.append(gate)
        return bundle
