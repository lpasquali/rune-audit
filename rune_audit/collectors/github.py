"""GitHub Actions artifact collector.

Collects SBOM, CVE scans, SLSA attestations, and gate results from
GitHub Actions across RUNE repositories.
"""

from __future__ import annotations

import io
import json
import logging
import os
import subprocess
import zipfile
from typing import Any

import httpx

from rune_audit.models.cve import CVEScanResult
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateResult
from rune_audit.models.sbom import SBOMDocument
from rune_audit.models.slsa import SLSAAttestation

logger = logging.getLogger(__name__)

RUNE_REPOS: list[str] = [
    "lpasquali/rune",
    "lpasquali/rune-operator",
    "lpasquali/rune-ui",
    "lpasquali/rune-charts",
    "lpasquali/rune-docs",
    "lpasquali/rune-audit",
]

GITHUB_API_BASE = "https://api.github.com"
SBOM_ARTIFACT_NAME = "sbom-security-outputs"
QUALITY_GATES_WORKFLOW = "quality-gates.yml"


def get_github_token() -> str:
    """Retrieve GitHub token from env or gh CLI."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
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


class GitHubCollector:
    """Collect evidence artifacts from GitHub Actions across RUNE repos."""

    def __init__(
        self,
        repos: list[str] | None = None,
        token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.repos = repos or list(RUNE_REPOS)
        self._token = token or get_github_token()
        self._client = client or httpx.Client(
            base_url=GITHUB_API_BASE,
            headers=self._build_headers(),
            timeout=30.0,
        )
        self._owns_client = client is None

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> GitHubCollector:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _get_latest_artifact(self, repo: str, artifact_name: str) -> dict[str, Any] | None:
        resp = self._client.get(
            f"/repos/{repo}/actions/artifacts",
            params={"name": artifact_name, "per_page": 1},
        )
        if resp.status_code != 200:
            logger.warning("Failed to list artifacts for %s: %s", repo, resp.status_code)
            return None
        data = resp.json()
        artifacts = data.get("artifacts", [])
        if not artifacts:
            return None
        return artifacts[0]

    def _download_artifact(self, repo: str, artifact_id: int) -> bytes | None:
        resp = self._client.get(
            f"/repos/{repo}/actions/artifacts/{artifact_id}/zip",
            follow_redirects=True,
        )
        if resp.status_code != 200:
            logger.warning("Failed to download artifact %d from %s: %s", artifact_id, repo, resp.status_code)
            return None
        return resp.content

    def _extract_json_from_zip(self, zip_bytes: bytes, filename: str) -> dict[str, Any] | None:
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                names = zf.namelist()
                target = None
                for name in names:
                    if name == filename or name.endswith("/" + filename) or name.endswith(filename):
                        target = name
                        break
                if target is None:
                    return None
                raw = zf.read(target)
                return json.loads(raw)
        except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
            logger.warning("Failed to extract %s from zip: %s", filename, exc)
            return None

    def collect_artifacts(
        self, repo: str, run_id: int | None = None
    ) -> tuple[SBOMDocument | None, CVEScanResult | None, CVEScanResult | None]:
        artifact_meta = self._get_latest_artifact(repo, SBOM_ARTIFACT_NAME)
        if artifact_meta is None:
            return None, None, None
        artifact_id = artifact_meta["id"]
        zip_bytes = self._download_artifact(repo, artifact_id)
        if zip_bytes is None:
            return None, None, None
        sbom = None
        sbom_data = self._extract_json_from_zip(zip_bytes, "rune-image.cdx.json")
        if sbom_data:
            sbom = SBOMDocument.from_cyclonedx(sbom_data, source_repo=repo)
        grype = None
        grype_data = self._extract_json_from_zip(zip_bytes, "rune-grype.json")
        if grype_data:
            grype = CVEScanResult.from_grype(grype_data, source_repo=repo)
        trivy = None
        trivy_data = self._extract_json_from_zip(zip_bytes, "rune-trivy.json")
        if trivy_data:
            trivy = CVEScanResult.from_trivy(trivy_data, source_repo=repo)
        return sbom, grype, trivy

    def collect_attestations(self, repo: str, subject_digest: str = "") -> list[SLSAAttestation]:
        if subject_digest:
            url = f"/repos/{repo}/attestations/sha256:{subject_digest}"
        else:
            url = f"/repos/{repo}/attestations"
        resp = self._client.get(url)
        if resp.status_code != 200:
            return []
        data = resp.json()
        attestations_raw = data.get("attestations", [])
        result: list[SLSAAttestation] = []
        for entry in attestations_raw:
            try:
                att = SLSAAttestation.from_github_attestation(entry, source_repo=repo)
                result.append(att)
            except Exception:
                logger.warning("Failed to parse attestation from %s", repo, exc_info=True)
        return result

    def collect_gate_results(self, repo: str, run_id: int | None = None) -> list[GateResult]:
        if run_id:
            runs_url = f"/repos/{repo}/actions/runs/{run_id}"
            resp = self._client.get(runs_url)
            if resp.status_code != 200:
                return []
            run_data = resp.json()
            workflow_name = run_data.get("name", "")
        else:
            resp = self._client.get(
                f"/repos/{repo}/actions/runs",
                params={"per_page": 1, "status": "completed"},
            )
            if resp.status_code != 200:
                return []
            runs = resp.json().get("workflow_runs", [])
            if not runs:
                return []
            run_data = runs[0]
            run_id = run_data["id"]
            workflow_name = run_data.get("name", "")
        resp = self._client.get(f"/repos/{repo}/actions/runs/{run_id}/jobs")
        if resp.status_code != 200:
            return []
        jobs = resp.json().get("jobs", [])
        results: list[GateResult] = []
        for job in jobs:
            gate = GateResult.from_github_job(
                job,
                source_repo=repo,
                workflow_run_id=run_id,
                workflow_name=workflow_name,
            )
            results.append(gate)
        return results

    def collect_all(self) -> EvidenceBundle:
        bundle = EvidenceBundle(repos=list(self.repos))
        for repo in self.repos:
            sbom, grype, trivy = self.collect_artifacts(repo)
            if sbom:
                bundle.sboms.append(sbom)
            if grype:
                bundle.cve_scans.append(grype)
            if trivy:
                bundle.cve_scans.append(trivy)
            attestations = self.collect_attestations(repo)
            bundle.slsa_attestations.extend(attestations)
            gates = self.collect_gate_results(repo)
            bundle.gate_results.extend(gates)
        return bundle
