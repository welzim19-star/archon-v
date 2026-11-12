# =============================================================================
# Archon-V — Demo & Playground Unit Tests
# File: tests/unit/test_demo.py
# =============================================================================

import hashlib
import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.mark.unit
class TestDemoPlayground:
    """Test suite for the interactive DevSecOps playground."""

    def test_playground_root_returns_html(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Archon-V" in response.text
        assert "DevSecOps Pre-Flight Gate" in response.text

    def test_playground_alias_returns_html(self, client: TestClient) -> None:
        response = client.get("/api/v1/demo")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Archon-V" in response.text

    def test_demo_health_endpoint(self, client: TestClient) -> None:
        response = client.get("/api/v1/demo/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert data["rules_active"]["secrets_regex_count"] > 0
        assert data["rules_active"]["pii_regex_count"] > 0

    def test_demo_scan_clean_code_allowed(self, client: TestClient) -> None:
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        response = client.post(
            "/api/v1/demo/scan",
            json={"content": code, "filename": "math.py", "scanner_type": "all"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "ALLOWED"
        assert len(data["findings"]) == 0
        assert data["latency_ms"] >= 0
        expected_sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
        assert data["content_sha256"] == expected_sha
        assert len(data["audit_hash"]) == 64

    def test_demo_scan_aws_key_blocked(self, client: TestClient) -> None:
        bad_code = 'AWS_KEY = "AKIA1234567890ABCDEF"\n'
        response = client.post(
            "/api/v1/demo/scan",
            json={"content": bad_code, "filename": "config.py", "scanner_type": "secrets"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "BLOCKED"
        assert len(data["findings"]) >= 1
        assert any(f["rule_id"] == "SEC-AWS-001" for f in data["findings"])

    def test_demo_scan_cpf_pii_blocked(self, client: TestClient) -> None:
        bad_code = 'USER_CPF = "123.456.789-00"\n'
        response = client.post(
            "/api/v1/demo/scan",
            json={"content": bad_code, "filename": "customer.py", "scanner_type": "pii"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "BLOCKED"
        assert len(data["findings"]) >= 1
        assert any(f["rule_id"] == "PII-CPF-BR-001" for f in data["findings"])

    def test_demo_scan_respects_scanner_type_filter(self, client: TestClient) -> None:
        # PII present, but scanner_type='secrets' only
        code_with_cpf = 'CPF = "987.654.321-11"\n'
        response = client.post(
            "/api/v1/demo/scan",
            json={"content": code_with_cpf, "filename": "data.py", "scanner_type": "secrets"},
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "ALLOWED"

    def test_demo_rate_limiter_burst_protection(self, client: TestClient) -> None:
        # Rapidly exhaust demo token bucket (burst capacity = 8)
        statuses = []
        for i in range(12):
            res = client.post(
                "/api/v1/demo/scan",
                headers={"X-Forwarded-For": "198.51.100.42"},
                json={"content": f"x = {i}", "filename": "burst.py"},
            )
            statuses.append(res.status_code)

        assert 429 in statuses
        # Verify 429 response body format
        rate_limited_idx = statuses.index(429)
        retry_res = client.post(
            "/api/v1/demo/scan",
            headers={"X-Forwarded-For": "198.51.100.42"},
            json={"content": "x = 99", "filename": "burst.py"},
        )
        if retry_res.status_code == 429:
            data = retry_res.json()
            assert data["error_code"] == "ERR_RATE_LIMITED"
            assert data["verdict"] == "RATE_LIMITED"
            assert retry_res.headers.get("retry-after") == "1"
