"""SLSA (Supply-chain Levels for Software Artifacts) attestation models.

Models for SLSA L3 build provenance attestations as produced by
actions/attest-build-provenance@v2.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SLSAAttestation(BaseModel):
    """An SLSA build provenance attestation."""

    subject_digest: str = Field(default="", description="Subject artifact digest (sha256)")
    subject_name: str = Field(default="", description="Subject artifact name")
    predicate_type: str = Field(default="", description="Attestation predicate type URI")
    builder_id: str = Field(default="", description="Builder identity URI")
    build_type: str = Field(default="", description="Build type URI")
    build_timestamp: datetime | None = Field(default=None, description="Build timestamp")
    provenance_uri: str = Field(default="", description="URI to the attestation bundle")
    source_repo: str = Field(default="", description="Source repository")
    source_ref: str = Field(default="", description="Source ref (tag, branch, commit)")
    invocation_id: str = Field(default="", description="Build invocation (workflow run) ID")
    verified: bool = Field(default=False, description="Whether attestation signature was verified")

    @classmethod
    def from_github_attestation(cls, data: dict[str, Any], source_repo: str = "") -> SLSAAttestation:
        """Parse a GitHub attestation API response entry.

        Args:
            data: A single attestation entry from the GitHub Attestations API.
            source_repo: Repository that produced the attestation.

        Returns:
            Parsed SLSAAttestation instance.
        """
        bundle = data.get("bundle", {})
        dsse_envelope = bundle.get("dsseEnvelope", {})

        # Decode the in-toto statement from the payload
        statement: dict[str, Any] = {}
        payload = dsse_envelope.get("payload", "")
        if payload:
            try:
                decoded = base64.b64decode(payload)
                statement = json.loads(decoded)
            except (ValueError, json.JSONDecodeError):
                pass

        # Extract subject
        subjects = statement.get("subject", [])
        subject_digest = ""
        subject_name = ""
        if subjects:
            subject = subjects[0]
            subject_name = subject.get("name", "")
            digests = subject.get("digest", {})
            subject_digest = digests.get("sha256", "")

        predicate = statement.get("predicate", {})
        predicate_type = statement.get("predicateType", dsse_envelope.get("payloadType", ""))

        # Builder
        run_details = predicate.get("runDetails", {})
        builder = run_details.get("builder", predicate.get("builder", {}))
        builder_id = builder.get("id", "")

        # Build type
        build_def = predicate.get("buildDefinition", {})
        build_type = build_def.get("buildType", predicate.get("buildType", ""))

        # Timestamp
        build_timestamp = None
        metadata = predicate.get("metadata", run_details.get("metadata", {}))
        ts_str = metadata.get("buildStartedOn", metadata.get("buildFinishedOn"))
        if ts_str:
            build_timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

        # Source ref from resolved dependencies
        source_ref = ""
        resolved = build_def.get("resolvedDependencies", [])
        for dep in resolved:
            uri = dep.get("uri", "")
            if "github.com" in uri:
                digest = dep.get("digest", {})
                source_ref = digest.get("gitCommit", "")
                break

        return cls(
            subject_digest=subject_digest,
            subject_name=subject_name,
            predicate_type=predicate_type,
            builder_id=builder_id,
            build_type=build_type,
            build_timestamp=build_timestamp,
            provenance_uri=str(data.get("repositoryId", "")),
            source_repo=source_repo,
            source_ref=source_ref,
            invocation_id="",
            verified=False,
        )
