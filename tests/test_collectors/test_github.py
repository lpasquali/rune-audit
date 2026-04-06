"""Tests for GitHub Actions artifact collector."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any
from unittest.mock import patch

import httpx

from rune_audit.collectors.github import GitHubCollector, get_github_token


def _make_artifact_zip(files: dict[str, dict[str, Any]]) -> bytes:
    """Create a zip file with the given JSON files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, json.dumps(data))
    return buf.getvalue()


class TestGetGithubToken:
    def test_from_github_token_env(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok123"}, clear=False):
            assert get_github_token() == "tok123"

    def test_from_rune_audit_env(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "", "RUNE_AUDIT_GITHUB_TOKEN": "tok456"}, clear=False):
            assert get_github_token() == "tok456"

    def test_from_gh_cli(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "", "RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.stdout = "gh-token\n"
                mock_run.return_value.returncode = 0
                token = get_github_token()
                assert token == "gh-token"

    def test_no_token_available(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "", "RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                assert get_github_token() == ""


class TestGitHubCollector:
    def _make_collector(self, responses: list[tuple[str, int, Any]]) -> GitHubCollector:
        resp_map: dict[str, tuple[int, Any]] = {}
        for path, status, body in responses:
            resp_map[path] = (status, body)

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path in resp_map:
                status, body = resp_map[path]
                if isinstance(body, bytes):
                    return httpx.Response(status, content=body)
                return httpx.Response(status, json=body)
            for key in resp_map:
                if path.startswith(key) or key in path:
                    status, body = resp_map[key]
                    if isinstance(body, bytes):
                        return httpx.Response(status, content=body)
                    return httpx.Response(status, json=body)
            return httpx.Response(404, json={"message": "Not Found"})

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport, base_url="https://api.github.com")
        return GitHubCollector(repos=["lpasquali/rune"], token="test-token", client=client)

    def test_collect_artifacts(self) -> None:
        sbom_data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"timestamp": "2026-04-01T00:00:00Z"}, "components": [{"name": "pkg", "version": "1.0"}]}
        grype_data = {"matches": [{"vulnerability": {"id": "CVE-X", "severity": "High"}, "artifact": {"name": "pkg", "version": "1.0"}}], "descriptor": {}}
        trivy_data = {"ArtifactName": "test", "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-Y", "Severity": "LOW", "PkgName": "p"}]}]}
        zip_bytes = _make_artifact_zip({"sbom/rune-image.cdx.json": sbom_data, "sbom/rune-grype.json": grype_data, "sbom/rune-trivy.json": trivy_data})
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/artifacts", 200, {"artifacts": [{"id": 1}]}),
            ("/repos/lpasquali/rune/actions/artifacts/1/zip", 200, zip_bytes),
        ])
        sbom, grype, trivy = collector.collect_artifacts("lpasquali/rune")
        assert sbom is not None
        assert len(sbom.components) == 1
        assert grype is not None
        assert len(grype.findings) == 1
        assert trivy is not None
        assert len(trivy.findings) == 1
        collector.close()

    def test_collect_artifacts_no_artifact(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/actions/artifacts", 200, {"artifacts": []})])
        sbom, grype, trivy = collector.collect_artifacts("lpasquali/rune")
        assert sbom is None and grype is None and trivy is None
        collector.close()

    def test_collect_artifacts_api_error(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/actions/artifacts", 500, {"message": "error"})])
        sbom, grype, trivy = collector.collect_artifacts("lpasquali/rune")
        assert sbom is None
        collector.close()

    def test_collect_artifacts_download_error(self) -> None:
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/artifacts", 200, {"artifacts": [{"id": 1}]}),
            ("/repos/lpasquali/rune/actions/artifacts/1/zip", 500, b"error"),
        ])
        sbom, grype, trivy = collector.collect_artifacts("lpasquali/rune")
        assert sbom is None
        collector.close()

    def test_collect_attestations(self) -> None:
        import base64
        statement = {"subject": [{"name": "test", "digest": {"sha256": "abc"}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {}, "runDetails": {"builder": {"id": "builder"}, "metadata": {}}}}
        payload = base64.b64encode(json.dumps(statement).encode()).decode()
        collector = self._make_collector([("/repos/lpasquali/rune/attestations", 200, {"attestations": [{"bundle": {"dsseEnvelope": {"payload": payload, "payloadType": "application/vnd.in-toto+json"}}}]})])
        atts = collector.collect_attestations("lpasquali/rune")
        assert len(atts) == 1
        assert atts[0].subject_digest == "abc"
        collector.close()

    def test_collect_attestations_not_found(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/attestations", 404, {"message": "Not Found"})])
        assert collector.collect_attestations("lpasquali/rune") == []
        collector.close()

    def test_collect_gate_results(self) -> None:
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/runs", 200, {"workflow_runs": [{"id": 100, "name": "Quality Gates"}]}),
            ("/repos/lpasquali/rune/actions/runs/100/jobs", 200, {"jobs": [{"id": 1, "name": "security-secrets", "conclusion": "success", "completed_at": "2026-04-01T00:00:00Z"}, {"id": 2, "name": "sast", "conclusion": "failure"}]}),
        ])
        gates = collector.collect_gate_results("lpasquali/rune")
        assert len(gates) == 2
        assert gates[0].status.value == "pass"
        assert gates[1].status.value == "fail"
        collector.close()

    def test_collect_gate_results_with_run_id(self) -> None:
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/runs/42", 200, {"id": 42, "name": "QG"}),
            ("/repos/lpasquali/rune/actions/runs/42/jobs", 200, {"jobs": [{"id": 1, "name": "test", "conclusion": "success"}]}),
        ])
        gates = collector.collect_gate_results("lpasquali/rune", run_id=42)
        assert len(gates) == 1
        collector.close()

    def test_collect_gate_results_no_runs(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/actions/runs", 200, {"workflow_runs": []})])
        assert collector.collect_gate_results("lpasquali/rune") == []
        collector.close()

    def test_collect_all(self) -> None:
        zip_bytes = _make_artifact_zip({"sbom/rune-image.cdx.json": {"bomFormat": "CycloneDX", "components": [{"name": "a"}]}})
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/artifacts", 200, {"artifacts": [{"id": 1}]}),
            ("/repos/lpasquali/rune/actions/artifacts/1/zip", 200, zip_bytes),
            ("/repos/lpasquali/rune/attestations", 200, {"attestations": []}),
            ("/repos/lpasquali/rune/actions/runs", 200, {"workflow_runs": []}),
        ])
        bundle = collector.collect_all()
        assert len(bundle.sboms) == 1
        assert len(bundle.repos) == 1
        collector.close()

    def test_context_manager(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(404))
        client = httpx.Client(transport=transport, base_url="https://api.github.com")
        with GitHubCollector(repos=[], token="t", client=client) as collector:
            assert collector is not None

    def test_extract_bad_zip(self) -> None:
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/artifacts", 200, {"artifacts": [{"id": 1}]}),
            ("/repos/lpasquali/rune/actions/artifacts/1/zip", 200, b"not a zip file"),
        ])
        sbom, grype, trivy = collector.collect_artifacts("lpasquali/rune")
        assert sbom is None
        collector.close()

    def test_collect_attestations_with_digest(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/attestations/sha256:abc", 200, {"attestations": []})])
        assert collector.collect_attestations("lpasquali/rune", subject_digest="abc") == []
        collector.close()

    def test_collect_gate_results_run_api_error(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/actions/runs/99", 404, {"message": "Not Found"})])
        assert collector.collect_gate_results("lpasquali/rune", run_id=99) == []
        collector.close()

    def test_collect_gate_results_jobs_api_error(self) -> None:
        collector = self._make_collector([
            ("/repos/lpasquali/rune/actions/runs", 200, {"workflow_runs": [{"id": 100, "name": "QG"}]}),
            ("/repos/lpasquali/rune/actions/runs/100/jobs", 500, {"message": "error"}),
        ])
        assert collector.collect_gate_results("lpasquali/rune") == []
        collector.close()

    def test_collect_runs_api_error(self) -> None:
        collector = self._make_collector([("/repos/lpasquali/rune/actions/runs", 500, {"message": "error"})])
        assert collector.collect_gate_results("lpasquali/rune") == []
        collector.close()


class TestGitHubCollectorEdgeCases:
    def test_default_init(self) -> None:
        """Test init without client."""
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_TOKEN": "tok", "RUNE_AUDIT_GITHUB_TOKEN": ""}):
            c = GitHubCollector(repos=["lpasquali/rune"])
            assert c._owns_client is True
            c.close()

    def test_headers_with_token(self) -> None:
        collector = GitHubCollector.__new__(GitHubCollector)
        collector._token = "my-token"
        headers = collector._build_headers()
        assert headers["Authorization"] == "Bearer my-token"

    def test_headers_without_token(self) -> None:
        collector = GitHubCollector.__new__(GitHubCollector)
        collector._token = ""
        headers = collector._build_headers()
        assert "Authorization" not in headers

    def test_extract_json_missing_file(self) -> None:
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("other.json", "{}")
        collector = GitHubCollector.__new__(GitHubCollector)
        result = collector._extract_json_from_zip(buf.getvalue(), "nonexistent.json")
        assert result is None
