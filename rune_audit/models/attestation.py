# SPDX-License-Identifier: Apache-2.0
"""TPM2 attestation models for hardware-rooted trust verification."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class PCRBank(BaseModel):
    """PCR (Platform Configuration Register) bank values."""

    algorithm: str = Field(description="Hash algorithm (e.g. sha1, sha256)")
    values: dict[int, str] = Field(default_factory=dict, description="PCR index to hex digest mapping")


class TPM2Quote(BaseModel):
    """TPM2 attestation quote."""

    pcr_selection: list[int] = Field(default_factory=list, description="Selected PCR indices")
    quote_data: str = Field(default="", description="Base64-encoded quote data")
    signature: str = Field(default="", description="Base64-encoded quote signature")
    pcr_digest: str = Field(default="", description="Combined PCR digest")
    nonce: str | None = Field(default=None, description="Anti-replay nonce")


class EventLogEntry(BaseModel):
    """A single entry in the TPM2 event log."""

    pcr_index: int = Field(description="PCR index this event extends")
    event_type: str = Field(description="Type of event (e.g. EV_POST_CODE, EV_SEPARATOR)")
    digest: str = Field(description="Hex-encoded event digest")
    event_data: str = Field(default="", description="Human-readable event data")


class TPM2EventLog(BaseModel):
    """TPM2 event log containing measurement entries."""

    entries: list[EventLogEntry] = Field(default_factory=list, description="Event log entries")


class PlatformState(BaseModel):
    """Platform security state from TPM2 attestation."""

    pcr_banks: list[PCRBank] = Field(default_factory=list, description="PCR bank readings")
    secure_boot: bool | None = Field(default=None, description="Whether Secure Boot is enabled")
    firmware_version: str | None = Field(default=None, description="Platform firmware version")


class AttestationResult(BaseModel):
    """Result from TPM2 attestation verification.

    Maintains backward compatibility with the original simple model
    while adding full TPM2 attestation fields.
    """

    passed: bool = Field(description="Whether attestation passed")
    pcr_digest: str = Field(default="", description="PCR digest value")
    message: str = Field(default="", description="Human-readable result message")
    quote: TPM2Quote | None = Field(default=None, description="TPM2 quote data")
    event_log: TPM2EventLog | None = Field(default=None, description="TPM2 event log")
    platform_state: PlatformState | None = Field(default=None, description="Platform security state")
    verified: bool = Field(default=False, description="Whether TPM2 verification succeeded")
    errors: list[str] = Field(default_factory=list, description="Error messages from collection/verification")
    collected_at: datetime | None = Field(default=None, description="Timestamp of attestation collection")
