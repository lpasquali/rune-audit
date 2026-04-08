# SPDX-License-Identifier: Apache-2.0
"""Tests for operator collector."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from unittest.mock import MagicMock

from rune_audit.collectors.operator import (
    OperatorCollector,
    _parse_events,
    _parse_run_record,
)
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateStatus
from rune_audit.models.operator import AuditEvent, AuditTrail, RunRecord


def _make_cr(
    name: str = "bench-1",
    namespace: str = "default",
    phase: str = "Complete",
    agent: str = "k8sgpt",
    model: str = "llama3.1:8b",
) -> dict:
    """Create a minimal RuneBenchmark CR dict."""
    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "creationTimestamp": "2026-04-01T10:00:00Z",
        },
        "spec": {
            "agent": agent,
            "model": model,
            "backendType": "ollama",
            "costEstimation": {"provider": "local"},
        },
        "status": {
            "phase": phase,
            "completedAt": "2026-04-01T10:05:00Z",
            "result": {"score": 0.85},
        },
    }


def _make_event(
    name: str = "bench-1",
    reason: str = "Created",
    message: str = "RuneBenchmark created",
    timestamp: str = "2026-04-01T10:00:00Z",
) -> dict:
    return {
        "involvedObject": {"name": name},
        "reason": reason,
        "message": message,
        "lastTimestamp": timestamp,
        "type": "Normal",
        "count": 1,
    }


class TestParseRunRecord:
    def test_parse_complete_cr(self) -> None:
        cr = _make_cr()
        record = _parse_run_record(cr)
        assert record.name == "bench-1"
        assert record.namespace == "default"
        assert record.status == "Complete"
        assert record.agent == "k8sgpt"
        assert record.model == "llama3.1:8b"
        assert record.backend_type == "ollama"
        assert record.result == {"score": 0.85}
        assert record.cost_estimation == {"provider": "local"}
        assert record.completed_at is not None

    def test_parse_minimal_cr(self) -> None:
        cr = {"metadata": {"name": "x", "creationTimestamp": "2026-01-01T00:00:00Z"}, "spec": {}, "status": {}}
        record = _parse_run_record(cr)
        assert record.name == "x"
        assert record.status == "Unknown"
        assert record.agent == ""
        assert record.completed_at is None

    def test_parse_missing_timestamp(self) -> None:
        cr = {"metadata": {"name": "x"}, "spec": {}, "status": {}}
        record = _parse_run_record(cr)
        assert record.name == "x"
        assert record.created_at is not None


class TestParseEvents:
    def test_parse_events(self) -> None:
        events_data = [
            _make_event(timestamp="2026-04-01T10:00:00Z", reason="Created"),
            _make_event(timestamp="2026-04-01T10:01:00Z", reason="Running"),
            _make_event(name="other", timestamp="2026-04-01T10:02:00Z"),
        ]
        result = _parse_events(events_data, "bench-1")
        assert len(result) == 2
        assert result[0].event_type == "Created"
        assert result[1].event_type == "Running"

    def test_parse_events_empty_timestamp(self) -> None:
        events_data = [{"involvedObject": {"name": "bench-1"}, "reason": "X", "lastTimestamp": "", "firstTimestamp": ""}]
        result = _parse_events(events_data, "bench-1")
        assert len(result) == 0

    def test_parse_events_empty_list(self) -> None:
        assert _parse_events([], "bench-1") == []


class TestOperatorCollector:
    def test_collect_run_records(self) -> None:
        cr_list = {"items": [_make_cr("a"), _make_cr("b")]}
        kubectl_fn = MagicMock(return_value=json.dumps(cr_list))
        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        records = collector.collect_run_records(namespace="test")
        assert len(records) == 2
        assert records[0].name == "a"
        kubectl_fn.assert_called_once()
        call_args = kubectl_fn.call_args[0][0]
        assert "-n" in call_args
        assert "test" in call_args

    def test_collect_run_records_all_namespaces(self) -> None:
        cr_list = {"items": [_make_cr()]}
        kubectl_fn = MagicMock(return_value=json.dumps(cr_list))
        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        records = collector.collect_run_records()
        assert len(records) == 1
        call_args = kubectl_fn.call_args[0][0]
        assert "--all-namespaces" in call_args

    def test_collect_run_records_failure(self) -> None:
        kubectl_fn = MagicMock(side_effect=subprocess.CalledProcessError(1, "kubectl"))
        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        records = collector.collect_run_records()
        assert records == []

    def test_collect_run_records_timeout(self) -> None:
        kubectl_fn = MagicMock(side_effect=subprocess.TimeoutExpired("kubectl", 30))
        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        records = collector.collect_run_records()
        assert records == []

    def test_collect_run_records_invalid_json(self) -> None:
        kubectl_fn = MagicMock(return_value="not json")
        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        records = collector.collect_run_records()
        assert records == []

    def test_collect_audit_trail(self) -> None:
        cr = _make_cr("bench-1")
        events = {"items": [
            _make_event("bench-1", "Created", "cr created", "2026-04-01T10:00:00Z"),
            _make_event("bench-1", "Running", "job started", "2026-04-01T10:01:00Z"),
        ]}

        def kubectl_fn(args, timeout=30):
            if "events" in args:
                return json.dumps(events)
            return json.dumps(cr)

        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        trail = collector.collect_audit_trail("bench-1")
        assert trail.run_name == "bench-1"
        assert len(trail.records) == 1
        assert len(trail.events) == 2
        assert trail.events[0].event_type == "Created"

    def test_collect_audit_trail_cr_failure(self) -> None:
        call_count = 0

        def kubectl_fn(args, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise subprocess.CalledProcessError(1, "kubectl")
            return json.dumps({"items": []})

        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        trail = collector.collect_audit_trail("missing")
        assert trail.records == []
        assert trail.events == []

    def test_collect_audit_trail_events_failure(self) -> None:
        cr = _make_cr("bench-1")
        call_count = 0

        def kubectl_fn(args, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise subprocess.CalledProcessError(1, "kubectl")
            return json.dumps(cr)

        collector = OperatorCollector(kubectl_fn=kubectl_fn)
        trail = collector.collect_audit_trail("bench-1")
        assert len(trail.records) == 1
        assert trail.events == []

    def test_enrich_evidence(self) -> None:
        bundle = EvidenceBundle()
        records = [
            RunRecord(
                name="bench-1", namespace="default", status="Complete",
                agent="k8sgpt", model="llama3.1:8b",
                created_at=datetime(2026, 4, 1, tzinfo=UTC),
                completed_at=datetime(2026, 4, 1, 0, 5, tzinfo=UTC),
            ),
            RunRecord(
                name="bench-2", namespace="default", status="Failed",
                agent="holmes", model="llama3.1:8b",
                created_at=datetime(2026, 4, 1, tzinfo=UTC),
            ),
        ]
        collector = OperatorCollector()
        result = collector.enrich_evidence(bundle, records)
        assert len(result.gate_results) == 2
        assert result.gate_results[0].status == GateStatus.PASS
        assert result.gate_results[1].status == GateStatus.FAIL

    def test_enrich_evidence_pending(self) -> None:
        bundle = EvidenceBundle()
        records = [
            RunRecord(
                name="bench-3", namespace="default", status="Pending",
                created_at=datetime(2026, 4, 1, tzinfo=UTC),
            ),
        ]
        collector = OperatorCollector()
        result = collector.enrich_evidence(bundle, records)
        assert result.gate_results[0].status == GateStatus.PENDING

    def test_enrich_evidence_unknown_status(self) -> None:
        bundle = EvidenceBundle()
        records = [
            RunRecord(
                name="bench-4", namespace="default", status="WeirdStatus",
                created_at=datetime(2026, 4, 1, tzinfo=UTC),
            ),
        ]
        collector = OperatorCollector()
        result = collector.enrich_evidence(bundle, records)
        assert result.gate_results[0].status == GateStatus.SKIP


class TestRunRecordModel:
    def test_serialization(self) -> None:
        record = RunRecord(
            name="bench-1", namespace="test",
            status="Complete", agent="k8sgpt", model="llama3.1:8b",
            created_at=datetime(2026, 4, 1, tzinfo=UTC),
        )
        data = record.model_dump()
        assert data["name"] == "bench-1"
        restored = RunRecord.model_validate(data)
        assert restored.name == record.name

    def test_json_roundtrip(self) -> None:
        record = RunRecord(
            name="x", created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        restored = RunRecord.model_validate_json(record.model_dump_json())
        assert restored.name == "x"


class TestAuditTrailModel:
    def test_serialization(self) -> None:
        trail = AuditTrail(
            run_name="bench-1",
            events=[AuditEvent(
                timestamp=datetime(2026, 4, 1, tzinfo=UTC),
                event_type="Created", message="test",
            )],
        )
        data = trail.model_dump()
        assert data["run_name"] == "bench-1"
        assert len(data["events"]) == 1
        restored = AuditTrail.model_validate(data)
        assert restored.run_name == trail.run_name
