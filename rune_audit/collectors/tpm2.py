# SPDX-License-Identifier: Apache-2.0
"""TPM2 attestation collector using tpm2-tools CLI subprocess."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from rune_audit.models.attestation import (
    AttestationResult,
    EventLogEntry,
    PCRBank,
    PlatformState,
    TPM2EventLog,
    TPM2Quote,
)


class TPM2Collector:
    """Collect TPM2 attestation evidence via tpm2-tools CLI.

    All TPM2 operations are performed through subprocess calls to
    tpm2_pcrread, tpm2_quote, and tpm2_eventlog commands.

    Args:
        tpm2_path_prefix: Path prefix for tpm2-tools binaries (default: empty, uses PATH).
        timeout: Subprocess timeout in seconds.
    """

    def __init__(self, tpm2_path_prefix: str = "", timeout: int = 30) -> None:
        self._prefix = tpm2_path_prefix
        self._timeout = timeout

    def _cmd(self, tool: str) -> str:
        """Return the full path to a tpm2 tool."""
        if self._prefix:
            return f"{self._prefix.rstrip('/')}/{tool}"
        return tool

    def collect_pcrs(self, pcr_selection: list[int] | None = None) -> PCRBank:
        """Read PCR values from the TPM2 device.

        Args:
            pcr_selection: PCR indices to read (default: [0, 1, 2, 3, 7]).

        Returns:
            A PCRBank with SHA-256 PCR values.

        Raises:
            RuntimeError: If tpm2_pcrread fails.
        """
        if pcr_selection is None:
            pcr_selection = [0, 1, 2, 3, 7]

        pcr_list = ",".join(str(i) for i in pcr_selection)
        result = subprocess.run(  # noqa: S603
            [self._cmd("tpm2_pcrread"), f"sha256:{pcr_list}"],
            capture_output=True,
            text=True,
            timeout=self._timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"tpm2_pcrread failed: {result.stderr.strip()}")

        return self._parse_pcr_output(result.stdout)

    def collect_quote(
        self,
        pcr_selection: list[int] | None = None,
        nonce: str | None = None,
    ) -> TPM2Quote:
        """Collect a TPM2 attestation quote.

        Args:
            pcr_selection: PCR indices to include in the quote.
            nonce: Optional anti-replay nonce.

        Returns:
            A TPM2Quote with quote data and signature.

        Raises:
            RuntimeError: If tpm2_quote fails.
        """
        if pcr_selection is None:
            pcr_selection = [0, 1, 2, 3, 7]

        pcr_list = ",".join(str(i) for i in pcr_selection)
        cmd = [
            self._cmd("tpm2_quote"),
            "--pcr-list",
            f"sha256:{pcr_list}",
        ]
        if nonce is not None:
            cmd.extend(["--qualification", nonce])

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=self._timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"tpm2_quote failed: {result.stderr.strip()}")

        return self._parse_quote_output(result.stdout, pcr_selection, nonce)

    def collect_event_log(self) -> TPM2EventLog:
        """Collect the TPM2 event log.

        Attempts to read from /sys/kernel/security/tpm0/binary_bios_measurements
        first, falling back to tpm2_eventlog command.

        Returns:
            A TPM2EventLog with parsed entries.

        Raises:
            RuntimeError: If event log collection fails.
        """
        bios_measurements = Path("/sys/kernel/security/tpm0/binary_bios_measurements")
        if bios_measurements.exists():
            result = subprocess.run(  # noqa: S603
                [self._cmd("tpm2_eventlog"), str(bios_measurements)],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        else:
            result = subprocess.run(  # noqa: S603
                [self._cmd("tpm2_eventlog")],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

        if result.returncode != 0:
            raise RuntimeError(f"tpm2_eventlog failed: {result.stderr.strip()}")

        return self._parse_event_log(result.stdout)

    def collect(self) -> AttestationResult:
        """Run the full TPM2 attestation collection pipeline.

        Collects PCRs, quote, and event log. Errors in individual
        steps are captured but do not prevent other steps from running.

        Returns:
            An AttestationResult with all collected data.
        """
        errors: list[str] = []
        pcr_bank: PCRBank | None = None
        quote: TPM2Quote | None = None
        event_log: TPM2EventLog | None = None

        try:
            pcr_bank = self.collect_pcrs()
        except RuntimeError as exc:
            errors.append(f"PCR collection failed: {exc}")

        try:
            quote = self.collect_quote()
        except RuntimeError as exc:
            errors.append(f"Quote collection failed: {exc}")

        try:
            event_log = self.collect_event_log()
        except RuntimeError as exc:
            errors.append(f"Event log collection failed: {exc}")

        platform_state = PlatformState(
            pcr_banks=[pcr_bank] if pcr_bank else [],
        )
        passed = len(errors) == 0

        return AttestationResult(
            passed=passed,
            pcr_digest=pcr_bank.values.get(0, "") if pcr_bank else "",
            message="TPM2 attestation collected" if passed else "; ".join(errors),
            quote=quote,
            event_log=event_log,
            platform_state=platform_state,
            verified=passed,
            errors=errors,
            collected_at=datetime.now(tz=UTC),
        )

    def _parse_pcr_output(self, output: str) -> PCRBank:
        """Parse tpm2_pcrread output into a PCRBank.

        Expected format:
          sha256:
            0 : 0x<hex>
            1 : 0x<hex>
        """
        values: dict[int, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            if ":" in stripped and "0x" in stripped:
                parts = stripped.split(":")
                if len(parts) >= 2:
                    idx_str = parts[0].strip()
                    val_str = parts[1].strip()
                    try:
                        idx = int(idx_str)
                        values[idx] = val_str.lower()
                    except ValueError:
                        continue
        return PCRBank(algorithm="sha256", values=values)

    def _parse_quote_output(
        self,
        output: str,
        pcr_selection: list[int],
        nonce: str | None,
    ) -> TPM2Quote:
        """Parse tpm2_quote output into a TPM2Quote.

        Expected format:
          quoted: <base64>
          signature: <base64>
          pcrs:
            sha256:
              <digest>
        """
        quote_data = ""
        signature = ""
        pcr_digest = ""

        lines = output.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("quoted:"):
                quote_data = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("signature:"):
                signature = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("pcrs:") or stripped.startswith("sha256:"):
                # Next non-empty, non-header line is the digest
                for j in range(i + 1, min(i + 5, len(lines))):
                    candidate = lines[j].strip()
                    if candidate and not candidate.endswith(":"):
                        pcr_digest = candidate
                        break

        return TPM2Quote(
            pcr_selection=pcr_selection,
            quote_data=quote_data,
            signature=signature,
            pcr_digest=pcr_digest,
            nonce=nonce,
        )

    def _parse_event_log(self, output: str) -> TPM2EventLog:
        """Parse tpm2_eventlog output into a TPM2EventLog.

        Expected YAML-like format:
          - PCRIndex: 0
            EventType: EV_POST_CODE
            Digests:
              - AlgorithmId: sha256
                Digest: "<hex>"
            Event: "<data>"
        """
        entries: list[EventLogEntry] = []
        current_pcr: int = -1
        current_type: str = ""
        current_digest: str = ""
        current_data: str = ""

        for line in output.splitlines():
            stripped = line.strip()

            if stripped.startswith("- PCRIndex:") or stripped.startswith("PCRIndex:"):
                # Save previous entry if valid
                if current_pcr >= 0:
                    entries.append(
                        EventLogEntry(
                            pcr_index=current_pcr,
                            event_type=current_type,
                            digest=current_digest,
                            event_data=current_data,
                        )
                    )
                val = stripped.split(":", 1)[1].strip()
                try:
                    current_pcr = int(val)
                except ValueError:
                    current_pcr = -1
                current_type = ""
                current_digest = ""
                current_data = ""

            elif stripped.startswith("EventType:"):
                current_type = stripped.split(":", 1)[1].strip()

            elif stripped.startswith("Digest:"):
                val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                if val:
                    current_digest = val

            elif stripped.startswith("Event:"):
                current_data = stripped.split(":", 1)[1].strip().strip('"').strip("'")

        # Don't forget the last entry
        if current_pcr >= 0:
            entries.append(
                EventLogEntry(
                    pcr_index=current_pcr,
                    event_type=current_type,
                    digest=current_digest,
                    event_data=current_data,
                )
            )

        return TPM2EventLog(entries=entries)
