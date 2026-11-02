# =============================================================================
# Archon-V — Unit Tests: Secret Scanner
# File: tests/unit/test_secrets.py
# =============================================================================
"""
Cobertura do SecretScanner:
  - Detecção de cada tipo de segredo suportado
  - Código limpo não gera falsos positivos
  - Limite de tamanho de diff (proteção ReDoS)
"""
import pytest

from core.interceptor.secrets import SecretScanner, SecretViolation


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner()


class TestSecretScannerDetection:
    """Verifica que segredos reais são detectados."""

    def test_detects_rsa_private_key(self, scanner):
        diff = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        violations = list(scanner.scan(diff))
        assert any(v.rule_id == "SEC-RSA-001" for v in violations)

    def test_detects_openssh_private_key(self, scanner):
        diff = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1..."
        violations = list(scanner.scan(diff))
        assert any(v.rule_id == "SEC-RSA-001" for v in violations)

    def test_detects_aws_access_key(self, scanner):
        diff = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE"
        violations = list(scanner.scan(diff))
        assert any(v.rule_id == "SEC-AWS-001" for v in violations)

    def test_detects_gcp_api_key(self, scanner):
        diff = "key = AIzaSyD-1234567890abcdefghijklmnopqrstu"
        violations = list(scanner.scan(diff))
        assert any(v.rule_id == "SEC-GCP-001" for v in violations)

    def test_detects_hardcoded_env_password(self, scanner):
        diff = 'password = "super_secret_password_123"'
        violations = list(scanner.scan(diff))
        assert any(v.rule_id == "SEC-ENV-001" for v in violations)

    def test_detects_hardcoded_env_token(self, scanner):
        diff = "token = 'ghp_abcdefghijklmnopqrstuvwxyz123456'"
        violations = list(scanner.scan(diff))
        assert any(v.rule_id == "SEC-ENV-001" for v in violations)


class TestSecretScannerCleanCode:
    """Verifica que código limpo não gera falsos positivos."""

    def test_clean_function_no_violations(self, scanner):
        diff = "def calculate_tax(value: float) -> float:\n    return value * 0.2\n"
        violations = list(scanner.scan(diff))
        assert violations == []

    def test_short_password_not_flagged(self, scanner):
        """Senhas curtas (< 10 chars) não devem ser flagadas para reduzir falsos positivos."""
        diff = "test_mode = 'ok'"
        violations = list(scanner.scan(diff))
        assert not any(v.rule_id == "SEC-ENV-001" for v in violations)

    def test_comment_code_clean(self, scanner):
        diff = "# This function processes payments\ndef process(): pass"
        violations = list(scanner.scan(diff))
        assert violations == []


class TestSecretScannerLimits:
    """Verifica o hard limit de tamanho de diff."""

    def test_oversized_diff_triggers_limit_violation(self, scanner):
        """Diff maior que 1MB deve retornar violação de limite, não crash."""
        oversized = "x" * (1_048_576 + 1)
        violations = list(scanner.scan(oversized))
        assert any(v.rule_id == "SEC-LIMIT-001" for v in violations)

    def test_exactly_1mb_is_scanned(self, scanner):
        """Exatamente 1MB deve ser aceito (< limite)."""
        exactly_1mb = "x" * 1_048_575
        # Não deve levantar exceção nem retornar limit violation
        violations = list(scanner.scan(exactly_1mb))
        assert not any(v.rule_id == "SEC-LIMIT-001" for v in violations)

    def test_empty_diff_is_clean(self, scanner):
        violations = list(scanner.scan(""))
        assert violations == []
