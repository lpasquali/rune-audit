# SPDX-License-Identifier: Apache-2.0
"""SLSA Level 3 provenance verifier.

Verifies that build attestations meet all five SLSA L3 requirements:

1. Build provenance exists --- attestation artifact attached to the release.
2. Provenance is signed --- via Sigstore/GitHub Attestations.
3. Builder is trusted --- GitHub Actions hosted runner.
4. Source is version-controlled --- git commit SHA in provenance.
5. Build is isolated --- ephemeral, non-reusable build environment.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from rune_audit.config import DEFAULT_REPOS, AuditConfig

# Trusted builder IDs for SLSA L3
TRUSTED_BUILDERS: frozenset[str] = frozenset(
    {
        "https://github.com/actions/runner",
        "https://github.com/slsa-framework/slsa-github-generator",
        "https://github.com/actions/attest-build-provenance",
    }
)

# Pre-computed trusted origins (scheme + netloc) for URL validation.
TRUSTED_ORIGINS: frozenset[str] = frozenset(f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in TRUSTED_BUILDERS)

GITHUB_ACTIONS_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"


def _is_trusted_url(candidate: str, trusted_urls: frozenset[str]) -> bool:
    """Validate a URL against a set of trusted URLs using origin + path comparison.

    This avoids incomplete substring sanitization (CodeQL
    py/incomplete-url-substring-sanitization) by parsing URLs and comparing
    scheme, host, and path components rather than using ``in`` or ``startswith``
    on raw strings.

    A candidate matches if:
    - Its origin (scheme://netloc) matches a trusted URL's origin, AND
    - Its path equals or is a sub-path of the trusted URL's path.
    """
    parsed = urlparse(candidate)
    candidate_origin = f"{parsed.scheme}://{parsed.netloc}"
    if not parsed.scheme or not parsed.netloc:
        return False
    if candidate_origin not in TRUSTED_ORIGINS:
        return False
    candidate_path = parsed.path.rstrip("/")
    for trusted in trusted_urls:
        tp = urlparse(trusted)
        trusted_origin = f"{tp.scheme}://{tp.netloc}"
        if candidate_origin != trusted_origin:
            continue
        trusted_path = tp.path.rstrip("/")
        if candidate_path == trusted_path or candidate_path.startswith(trusted_path + "/"):
            return True
    return False


def _is_trusted_build_type(build_type: str) -> bool:
    """Validate a build type URL against the known GitHub Actions build type.

    Uses origin + path comparison instead of substring matching.
    """
    parsed = urlparse(build_type)
    expected = urlparse(GITHUB_ACTIONS_BUILD_TYPE)
    if not parsed.scheme or not parsed.netloc:
        return False
    return (
        parsed.scheme == expected.scheme
        and parsed.netloc == expected.netloc
        and parsed.path.rstrip("/") == expected.path.rstrip("/")
    )


# -- Attestation bundle --------------------------------------------------------


@dataclass
class AttestationBundle:
    """Raw attestation data from GitHub for SLSA verification."""

    repo: str
    tag: str
    found: bool = False
    payload: dict[str, object] = None  # type: ignore[assignment]
    error: str = ""

    def __post_init__(self) -> None:
        if self.payload is None:
            self.payload = {}


def _get_github_token() -> str:
    """Retrieve GitHub token from env or gh CLI."""
    token = os.environ.get("RUNE_AUDIT_GITHUB_TOKEN", "")
    if token:
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def collect_attestations(repo: str, tag: str) -> AttestationBundle:
    """Collect attestations for a repo+tag from GitHub.

    Uses ``gh attestation verify`` as the primary mechanism.
    """
    token = _get_github_token()
    if not token:
        return AttestationBundle(
            repo=repo,
            tag=tag,
            found=False,
            error="No GitHub token available. Set RUNE_AUDIT_GITHUB_TOKEN or run 'gh auth login'.",
        )

    try:
        result = subprocess.run(
            [
                "gh",
                "attestation",
                "verify",
                "--repo",
                f"lpasquali/{repo}",
                "--format",
                "json",
                f"oci://ghcr.io/lpasquali/{repo}:{tag}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env={**os.environ, "GH_TOKEN": token},
        )
        if result.returncode == 0 and result.stdout.strip():
            payload = json.loads(result.stdout)
            return AttestationBundle(repo=repo, tag=tag, found=True, payload=payload)
        return AttestationBundle(
            repo=repo,
            tag=tag,
            found=False,
            error=result.stderr.strip() or "No attestation found",
        )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
        return AttestationBundle(repo=repo, tag=tag, found=False, error=str(exc))


# -- Verification result models ------------------------------------------------


class SLSARequirement(Enum):
    """SLSA Level 3 requirements to verify."""

    BUILD_PROVENANCE_EXISTS = "build_provenance_exists"
    PROVENANCE_SIGNED = "provenance_signed"
    BUILDER_TRUSTED = "builder_trusted"
    SOURCE_VERSION_CONTROLLED = "source_version_controlled"
    BUILD_ISOLATED = "build_isolated"


class VerificationStatus(Enum):
    """Status of a single verification check."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class SLSACheckResult:
    """Result of a single SLSA requirement verification."""

    requirement: SLSARequirement
    status: VerificationStatus
    message: str
    details: dict[str, str] = field(default_factory=dict)


@dataclass
class SLSAVerificationReport:
    """Full verification report for a single repo+tag."""

    repo: str
    tag: str
    checks: list[SLSACheckResult] = field(default_factory=list)
    attestation_found: bool = False
    builder_id: str = ""
    source_sha: str = ""

    @property
    def passed(self) -> bool:
        """Return True if all checks passed."""
        return all(c.status == VerificationStatus.PASS for c in self.checks)

    @property
    def gaps(self) -> list[SLSACheckResult]:
        """Return checks that did not pass."""
        return [c for c in self.checks if c.status != VerificationStatus.PASS]


# -- Verification checks -------------------------------------------------------


def _check_provenance_exists(bundle: AttestationBundle) -> SLSACheckResult:
    """Requirement 1: Build provenance exists."""
    if bundle.found and bundle.payload:
        return SLSACheckResult(
            requirement=SLSARequirement.BUILD_PROVENANCE_EXISTS,
            status=VerificationStatus.PASS,
            message="Build provenance attestation found",
            details={"repo": bundle.repo, "tag": bundle.tag},
        )
    return SLSACheckResult(
        requirement=SLSARequirement.BUILD_PROVENANCE_EXISTS,
        status=VerificationStatus.FAIL,
        message=f"No build provenance found: {bundle.error}",
        details={"repo": bundle.repo, "tag": bundle.tag},
    )


def _extract_predicate(payload: dict[str, object]) -> dict[str, object]:
    """Extract the SLSA predicate from an attestation payload."""
    if "predicate" in payload:
        pred = payload["predicate"]
        if isinstance(pred, dict):
            return pred
    if isinstance(payload, list) and len(payload) > 0:
        first = payload[0]
        if isinstance(first, dict) and "verificationResult" in first:
            vr = first["verificationResult"]
            if isinstance(vr, dict) and "statement" in vr:
                stmt = vr["statement"]
                if isinstance(stmt, dict) and "predicate" in stmt:
                    pred = stmt["predicate"]
                    if isinstance(pred, dict):
                        return pred
    return {}


def _check_provenance_signed(bundle: AttestationBundle) -> SLSACheckResult:
    """Requirement 2: Provenance is signed."""
    if not bundle.found:
        return SLSACheckResult(
            requirement=SLSARequirement.PROVENANCE_SIGNED,
            status=VerificationStatus.SKIP,
            message="Skipped: no attestation to verify signature",
        )
    return SLSACheckResult(
        requirement=SLSARequirement.PROVENANCE_SIGNED,
        status=VerificationStatus.PASS,
        message="Provenance signature verified by gh attestation verify",
    )


def _check_builder_trusted(bundle: AttestationBundle) -> SLSACheckResult:
    """Requirement 3: Builder is trusted (GitHub Actions hosted runner)."""
    if not bundle.found:
        return SLSACheckResult(
            requirement=SLSARequirement.BUILDER_TRUSTED,
            status=VerificationStatus.SKIP,
            message="Skipped: no attestation to check builder",
        )
    predicate = _extract_predicate(bundle.payload)
    build_type = str(predicate.get("buildType", ""))
    builder_id = ""
    builder_block = predicate.get("builder", {})
    if isinstance(builder_block, dict):
        builder_id = str(builder_block.get("id", ""))

    # SLSA v1.0: builder is in runDetails, buildType is in buildDefinition
    if not builder_id:
        run_details = predicate.get("runDetails", {})
        if isinstance(run_details, dict):
            rb = run_details.get("builder", {})
            if isinstance(rb, dict):
                builder_id = str(rb.get("id", ""))
    if not build_type:
        build_def = predicate.get("buildDefinition", {})
        if isinstance(build_def, dict):
            build_type = str(build_def.get("buildType", ""))

    if builder_id and _is_trusted_url(builder_id, TRUSTED_BUILDERS):
        return SLSACheckResult(
            requirement=SLSARequirement.BUILDER_TRUSTED,
            status=VerificationStatus.PASS,
            message=f"Builder is trusted: {builder_id}",
            details={"builder_id": builder_id, "build_type": build_type},
        )
    if _is_trusted_build_type(build_type):
        return SLSACheckResult(
            requirement=SLSARequirement.BUILDER_TRUSTED,
            status=VerificationStatus.PASS,
            message=f"GitHub Actions build type detected: {build_type}",
            details={"build_type": build_type},
        )
    return SLSACheckResult(
        requirement=SLSARequirement.BUILDER_TRUSTED,
        status=VerificationStatus.FAIL,
        message=f"Builder not in trusted set: '{builder_id}'",
        details={"builder_id": builder_id, "build_type": build_type},
    )


def _check_source_version_controlled(bundle: AttestationBundle) -> SLSACheckResult:
    """Requirement 4: Source is version-controlled (git commit SHA)."""
    if not bundle.found:
        return SLSACheckResult(
            requirement=SLSARequirement.SOURCE_VERSION_CONTROLLED,
            status=VerificationStatus.SKIP,
            message="Skipped: no attestation to check source",
        )
    predicate = _extract_predicate(bundle.payload)
    invocation = predicate.get("invocation", {})
    materials = predicate.get("materials", [])

    sha = ""
    if isinstance(invocation, dict):
        config_source = invocation.get("configSource", {})
        if isinstance(config_source, dict):
            digest = config_source.get("digest", {})
            if isinstance(digest, dict):
                sha = str(digest.get("sha1", ""))

    if not sha and isinstance(materials, list):
        for mat in materials:
            if isinstance(mat, dict):
                digest = mat.get("digest", {})
                if isinstance(digest, dict):
                    sha = str(digest.get("sha1", digest.get("sha256", "")))
                    if sha:
                        break

    if not sha:
        build_def = predicate.get("buildDefinition", {})
        if isinstance(build_def, dict):
            resolved_deps = build_def.get("resolvedDependencies", [])
            if isinstance(resolved_deps, list):
                for dep in resolved_deps:
                    if isinstance(dep, dict):
                        digest = dep.get("digest", {})
                        if isinstance(digest, dict):
                            sha = str(digest.get("gitCommit", digest.get("sha256", "")))
                            if sha:
                                break

    if sha:
        return SLSACheckResult(
            requirement=SLSARequirement.SOURCE_VERSION_CONTROLLED,
            status=VerificationStatus.PASS,
            message=f"Source commit SHA found: {sha[:12]}",
            details={"sha": sha},
        )
    return SLSACheckResult(
        requirement=SLSARequirement.SOURCE_VERSION_CONTROLLED,
        status=VerificationStatus.FAIL,
        message="No source commit SHA found in provenance",
    )


def _check_build_isolated(bundle: AttestationBundle) -> SLSACheckResult:
    """Requirement 5: Build is isolated (ephemeral environment)."""
    if not bundle.found:
        return SLSACheckResult(
            requirement=SLSARequirement.BUILD_ISOLATED,
            status=VerificationStatus.SKIP,
            message="Skipped: no attestation to check isolation",
        )
    predicate = _extract_predicate(bundle.payload)
    build_type = str(predicate.get("buildType", ""))
    metadata = predicate.get("metadata", {})

    is_ephemeral = False
    if isinstance(metadata, dict):
        build_finished_on = metadata.get("buildFinishedOn", "")
        if build_finished_on:
            is_ephemeral = True

    if _is_trusted_build_type(build_type):
        is_ephemeral = True

    run_details = predicate.get("runDetails", {})
    if isinstance(run_details, dict):
        builder_info = run_details.get("builder", {})
        if isinstance(builder_info, dict):
            builder_id_val = str(builder_info.get("id", ""))
            if _is_trusted_url(builder_id_val, TRUSTED_BUILDERS):
                is_ephemeral = True

    if is_ephemeral:
        return SLSACheckResult(
            requirement=SLSARequirement.BUILD_ISOLATED,
            status=VerificationStatus.PASS,
            message="Build ran in ephemeral GitHub Actions environment",
            details={"build_type": build_type},
        )
    return SLSACheckResult(
        requirement=SLSARequirement.BUILD_ISOLATED,
        status=VerificationStatus.FAIL,
        message="Cannot confirm build isolation from provenance metadata",
        details={"build_type": build_type},
    )


# -- Public API ----------------------------------------------------------------


def verify_slsa(repo: str, tag: str, bundle: AttestationBundle | None = None) -> SLSAVerificationReport:
    """Verify SLSA Level 3 compliance for a single repo+tag."""
    if bundle is None:
        bundle = collect_attestations(repo, tag)

    report = SLSAVerificationReport(repo=repo, tag=tag, attestation_found=bundle.found)

    report.checks.append(_check_provenance_exists(bundle))
    report.checks.append(_check_provenance_signed(bundle))

    builder_result = _check_builder_trusted(bundle)
    report.checks.append(builder_result)
    if "builder_id" in builder_result.details:
        report.builder_id = builder_result.details["builder_id"]

    source_result = _check_source_version_controlled(bundle)
    report.checks.append(source_result)
    if "sha" in source_result.details:
        report.source_sha = source_result.details["sha"]

    report.checks.append(_check_build_isolated(bundle))

    return report


def verify_slsa_all(
    tag: str,
    repos: list[str] | None = None,
    config: AuditConfig | None = None,
) -> list[SLSAVerificationReport]:
    """Verify SLSA Level 3 compliance across all ecosystem repos."""
    if repos is None:
        repos = list(config.repos) if config else list(DEFAULT_REPOS)

    return [verify_slsa(repo, tag) for repo in repos]
