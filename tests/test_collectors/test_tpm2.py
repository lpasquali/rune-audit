# SPDX-License-Identifier: Apache-2.0
"""Tests for the TPM2 attestation collector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from rune_audit.collectors.tpm2 import TPM2Collector
from rune_audit.models.attestation import (
    AttestationResult,
    EventLogEntry,
    PCRBank,
    PlatformState,
    TPM2EventLog,
    TPM2Quote,
)

# --- Model Tests ---


class TestPCRBank:
    """Tests for PCRBank model."""

    def test_create(self) -> None:
        bank = PCRBank(algorithm="sha256", values={0: "0xabc", 1: "0xdef"})
        assert bank.algorithm == "sha256"
        assert len(bank.values) == 2

    def test_empty_values(self) -> None:
        bank = PCRBank(algorithm="sha1")
        assert bank.values == {}

    def test_serialization(self) -> None:
        bank = PCRBank(algorithm="sha256", values={0: "0x00"})
        assert PCRBank.model_validate(bank.model_dump()) == bank


class TestTPM2Quote:
    """Tests for TPM2Quote model."""

    def test_create(self) -> None:
        quote = TPM2Quote(
            pcr_selection=[0, 1, 7],
            quote_data="base64data",
            signature="base64sig",
            pcr_digest="abc",
            nonce="test-nonce",
        )
        assert quote.pcr_selection == [0, 1, 7]
        assert quote.nonce == "test-nonce"

    def test_defaults(self) -> None:
        quote = TPM2Quote()
        assert quote.pcr_selection == []
        assert quote.nonce is None

    def test_serialization(self) -> None:
        quote = TPM2Quote(pcr_selection=[0], quote_data="q", signature="s", pcr_digest="d")
        assert TPM2Quote.model_validate(quote.model_dump()) == quote


class TestEventLogEntry:
    """Tests for EventLogEntry model."""

    def test_create(self) -> None:
        entry = EventLogEntry(pcr_index=0, event_type="EV_POST_CODE", digest="abc123")
        assert entry.pcr_index == 0
        assert entry.event_data == ""


class TestTPM2EventLog:
    """Tests for TPM2EventLog model."""

    def test_empty(self) -> None:
        log = TPM2EventLog()
        assert log.entries == []

    def test_with_entries(self) -> None:
        log = TPM2EventLog(
            entries=[
                EventLogEntry(pcr_index=0, event_type="EV_POST_CODE", digest="abc"),
                EventLogEntry(pcr_index=7, event_type="EV_SEPARATOR", digest="def"),
            ]
        )
        assert len(log.entries) == 2


class TestPlatformState:
    """Tests for PlatformState model."""

    def test_defaults(self) -> None:
        state = PlatformState()
        assert state.pcr_banks == []
        assert state.secure_boot is None
        assert state.firmware_version is None

    def test_full(self) -> None:
        state = PlatformState(
            pcr_banks=[PCRBank(algorithm="sha256", values={0: "abc"})],
            secure_boot=True,
            firmware_version="1.2.3",
        )
        assert state.secure_boot is True


class TestAttestationResultBackwardCompat:
    """Tests that AttestationResult remains backward-compatible."""

    def test_original_fields(self) -> None:
        r = AttestationResult(passed=True, pcr_digest="abc", message="OK")
        assert r.passed is True and r.pcr_digest == "abc"

    def test_original_defaults(self) -> None:
        r = AttestationResult(passed=False)
        assert r.pcr_digest == "" and r.message == ""

    def test_original_serialization(self) -> None:
        r = AttestationResult(passed=True, pcr_digest="xyz", message="v")
        assert AttestationResult.model_validate(r.model_dump()) == r

    def test_new_fields_default_none(self) -> None:
        r = AttestationResult(passed=True)
        assert r.quote is None
        assert r.event_log is None
        assert r.platform_state is None
        assert r.verified is False
        assert r.errors == []
        assert r.collected_at is None

    def test_full_attestation(self) -> None:
        r = AttestationResult(
            passed=True,
            pcr_digest="abc",
            message="Full TPM2",
            quote=TPM2Quote(pcr_selection=[0, 1]),
            event_log=TPM2EventLog(entries=[]),
            platform_state=PlatformState(secure_boot=True),
            verified=True,
            errors=[],
        )
        assert r.quote is not None
        assert r.platform_state is not None
        data = r.model_dump()
        restored = AttestationResult.model_validate(data)
        assert restored.quote is not None
        assert restored.platform_state is not None


# --- Collector Tests ---

PCR_OUTPUT = """\
sha256:
  0 : 0xaabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb
  1 : 0x1122334455667788990011223344556677889900112233445566778899001122
  2 : 0x0000000000000000000000000000000000000000000000000000000000000000
  3 : 0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
  7 : 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
"""

QUOTE_OUTPUT = """\
quoted: SGVsbG8gV29ybGQ=
signature: c2lnbmF0dXJlLWRhdGE=
pcrs:
  sha256:
    aabbccdd
"""

EVENT_LOG_OUTPUT = """\
- PCRIndex: 0
  EventType: EV_POST_CODE
  DigestCount: 1
  Digests:
    - AlgorithmId: sha256
      Digest: "abc123def456"
  Event: "POST CODE"
- PCRIndex: 7
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
    - AlgorithmId: sha256
      Digest: "separator_digest"
  Event: ""
"""


class TestTPM2CollectorConstructor:
    """Tests for TPM2Collector constructor."""

    def test_default(self) -> None:
        c = TPM2Collector()
        assert c._prefix == ""
        assert c._timeout == 30

    def test_custom(self) -> None:
        c = TPM2Collector(tpm2_path_prefix="/usr/local/bin", timeout=60)
        assert c._prefix == "/usr/local/bin"
        assert c._timeout == 60

    def test_cmd_with_prefix(self) -> None:
        c = TPM2Collector(tpm2_path_prefix="/opt/tpm2/bin")
        assert c._cmd("tpm2_pcrread") == "/opt/tpm2/bin/tpm2_pcrread"

    def test_cmd_without_prefix(self) -> None:
        c = TPM2Collector()
        assert c._cmd("tpm2_pcrread") == "tpm2_pcrread"

    def test_cmd_prefix_trailing_slash(self) -> None:
        c = TPM2Collector(tpm2_path_prefix="/opt/bin/")
        assert c._cmd("tpm2_pcrread") == "/opt/bin/tpm2_pcrread"


class TestTPM2CollectorPCRs:
    """Tests for TPM2Collector.collect_pcrs()."""

    def test_success(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = PCR_OUTPUT
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result) as mock_run:
            c = TPM2Collector()
            bank = c.collect_pcrs()

        mock_run.assert_called_once()
        assert bank.algorithm == "sha256"
        assert 0 in bank.values
        assert 7 in bank.values
        assert len(bank.values) == 5

    def test_custom_selection(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sha256:\n  0 : 0xaabb\n"
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result) as mock_run:
            c = TPM2Collector()
            c.collect_pcrs(pcr_selection=[0])

        cmd = mock_run.call_args[0][0]
        assert "sha256:0" in cmd[1]

    def test_failure(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ERROR: Could not access TPM"

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result):
            c = TPM2Collector()
            with pytest.raises(RuntimeError, match="tpm2_pcrread failed"):
                c.collect_pcrs()

    def test_parse_malformed_line(self) -> None:
        """Lines without 0x are skipped gracefully."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sha256:\n  not_a_number : 0xaabb\n  0 : 0xccdd\n"
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result):
            c = TPM2Collector()
            bank = c.collect_pcrs()
        assert 0 in bank.values
        assert len(bank.values) == 1


class TestTPM2CollectorQuote:
    """Tests for TPM2Collector.collect_quote()."""

    def test_success(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = QUOTE_OUTPUT
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result):
            c = TPM2Collector()
            quote = c.collect_quote()

        assert quote.quote_data == "SGVsbG8gV29ybGQ="
        assert quote.signature == "c2lnbmF0dXJlLWRhdGE="
        assert quote.pcr_digest == "aabbccdd"
        assert quote.pcr_selection == [0, 1, 2, 3, 7]

    def test_with_nonce(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = QUOTE_OUTPUT
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result) as mock_run:
            c = TPM2Collector()
            quote = c.collect_quote(nonce="test-nonce-123")

        cmd = mock_run.call_args[0][0]
        assert "--qualification" in cmd
        assert "test-nonce-123" in cmd
        assert quote.nonce == "test-nonce-123"

    def test_failure(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ERROR: No TPM device"

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result):
            c = TPM2Collector()
            with pytest.raises(RuntimeError, match="tpm2_quote failed"):
                c.collect_quote()

    def test_custom_pcrs(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "quoted: q\nsignature: s\n"
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result) as mock_run:
            c = TPM2Collector()
            quote = c.collect_quote(pcr_selection=[0, 7])

        cmd = mock_run.call_args[0][0]
        assert "sha256:0,7" in cmd[2]
        assert quote.pcr_selection == [0, 7]

    def test_empty_output(self) -> None:
        """Empty output produces a quote with empty fields."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result):
            c = TPM2Collector()
            quote = c.collect_quote()
        assert quote.quote_data == ""
        assert quote.signature == ""


class TestTPM2CollectorEventLog:
    """Tests for TPM2Collector.collect_event_log()."""

    def test_success_with_bios_file(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = EVENT_LOG_OUTPUT
        mock_result.stderr = ""

        with (
            patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result) as mock_run,
            patch("rune_audit.collectors.tpm2.Path.exists", return_value=True),
        ):
            c = TPM2Collector()
            log = c.collect_event_log()

        assert len(log.entries) == 2
        assert log.entries[0].pcr_index == 0
        assert log.entries[0].event_type == "EV_POST_CODE"
        assert log.entries[0].digest == "abc123def456"
        assert log.entries[0].event_data == "POST CODE"
        assert log.entries[1].pcr_index == 7
        # Check that bios_measurements path was passed
        cmd = mock_run.call_args[0][0]
        assert "binary_bios_measurements" in cmd[-1]

    def test_success_without_bios_file(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = EVENT_LOG_OUTPUT
        mock_result.stderr = ""

        with (
            patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result) as mock_run,
            patch("rune_audit.collectors.tpm2.Path.exists", return_value=False),
        ):
            c = TPM2Collector()
            log = c.collect_event_log()

        assert len(log.entries) == 2
        cmd = mock_run.call_args[0][0]
        assert len(cmd) == 1  # Just the tool name, no file argument

    def test_failure(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ERROR: No event log"

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            with pytest.raises(RuntimeError, match="tpm2_eventlog failed"):
                c.collect_event_log()

    def test_empty_event_log(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            log = c.collect_event_log()
        assert log.entries == []

    def test_parse_pcr_index_entry(self) -> None:
        """Test parsing entry starting with PCRIndex: (no dash)."""
        output = "PCRIndex: 0\nEventType: EV_NO_ACTION\nDigest: \"abc\"\nEvent: \"init\"\n"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = output
        mock_result.stderr = ""

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            log = c.collect_event_log()
        assert len(log.entries) == 1
        assert log.entries[0].event_type == "EV_NO_ACTION"


class TestTPM2CollectorFullPipeline:
    """Tests for TPM2Collector.collect() full pipeline."""

    def test_all_success(self) -> None:
        pcr_result = MagicMock()
        pcr_result.returncode = 0
        pcr_result.stdout = PCR_OUTPUT
        pcr_result.stderr = ""

        quote_result = MagicMock()
        quote_result.returncode = 0
        quote_result.stdout = QUOTE_OUTPUT
        quote_result.stderr = ""

        event_result = MagicMock()
        event_result.returncode = 0
        event_result.stdout = EVENT_LOG_OUTPUT
        event_result.stderr = ""

        def side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            if "tpm2_pcrread" in cmd[0]:
                return pcr_result
            if "tpm2_quote" in cmd[0]:
                return quote_result
            return event_result

        with patch("rune_audit.collectors.tpm2.subprocess.run", side_effect=side_effect), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            result = c.collect()

        assert result.passed is True
        assert result.verified is True
        assert result.errors == []
        assert result.quote is not None
        assert result.event_log is not None
        assert result.platform_state is not None
        assert len(result.platform_state.pcr_banks) == 1
        assert result.collected_at is not None

    def test_all_failures(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ERROR"

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            result = c.collect()

        assert result.passed is False
        assert result.verified is False
        assert len(result.errors) == 3
        assert "PCR collection failed" in result.errors[0]
        assert "Quote collection failed" in result.errors[1]
        assert "Event log collection failed" in result.errors[2]
        assert result.quote is None
        assert result.event_log is None

    def test_partial_failure(self) -> None:
        """PCRs succeed but quote and event log fail."""
        pcr_result = MagicMock()
        pcr_result.returncode = 0
        pcr_result.stdout = "sha256:\n  0 : 0xaabb\n"
        pcr_result.stderr = ""

        fail_result = MagicMock()
        fail_result.returncode = 1
        fail_result.stdout = ""
        fail_result.stderr = "No TPM"

        def side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            if "tpm2_pcrread" in cmd[0]:
                return pcr_result
            return fail_result

        with patch("rune_audit.collectors.tpm2.subprocess.run", side_effect=side_effect), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            result = c.collect()

        assert result.passed is False
        assert len(result.errors) == 2
        assert result.platform_state is not None
        assert len(result.platform_state.pcr_banks) == 1
        assert result.pcr_digest == "0xaabb"

    def test_no_tpm2_device(self) -> None:
        """Simulates FileNotFoundError (command not found)."""
        mock_result = MagicMock()
        mock_result.returncode = 127
        mock_result.stdout = ""
        mock_result.stderr = "tpm2_pcrread: command not found"

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            result = c.collect()

        assert result.passed is False
        assert len(result.errors) == 3

    def test_permission_denied(self) -> None:
        """Simulates permission denied error."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied: /dev/tpm0"

        with patch("rune_audit.collectors.tpm2.subprocess.run", return_value=mock_result), patch(
            "rune_audit.collectors.tpm2.Path.exists", return_value=False
        ):
            c = TPM2Collector()
            result = c.collect()

        assert result.passed is False
        assert any("Permission denied" in e for e in result.errors)
