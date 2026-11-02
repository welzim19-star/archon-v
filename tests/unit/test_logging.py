# =============================================================================
# Archon-V — Unit Tests: PII Scrubber (Observability)
# File: tests/unit/test_logging.py
# =============================================================================
"""
Testa que o sistema de logging NUNCA vaza PII ou segredos.
Este teste é evidência direta para auditoria SOC 2 e LGPD.
"""
import pytest
from core.observability.logging import scrub_pii


class TestPIIScrubber:
    """Garante que o scrubber remove todos os tipos de PII antes do log sink."""

    def test_scrubs_cpf(self):
        result = scrub_pii("User CPF: 123.456.789-09 logged in")
        assert "123.456.789-09" not in result
        assert "[CPF REDACTED]" in result

    def test_scrubs_email(self):
        result = scrub_pii("Contact: joao@empresa.com.br for support")
        assert "joao@empresa.com.br" not in result
        assert "[EMAIL REDACTED]" in result

    def test_scrubs_visa_card(self):
        result = scrub_pii("Payment with card 4532015112830366 processed")
        assert "4532015112830366" not in result
        assert "[CARD REDACTED]" in result

    def test_scrubs_aws_key(self):
        result = scrub_pii("Using key AKIAIOSFODNN7EXAMPLE for auth")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[AWS KEY REDACTED]" in result

    def test_scrubs_gcp_api_key(self):
        result = scrub_pii("GCP key: AIzaSyD-1234567890abcdefghijklmnopqrstu")
        assert "AIzaSyD" not in result
        assert "[GCP KEY REDACTED]" in result

    def test_scrubs_password_assignment(self):
        result = scrub_pii('password="minha_senha_secreta_123"')
        assert "minha_senha_secreta_123" not in result
        assert "[SECRET REDACTED]" in result

    def test_clean_message_unchanged(self):
        msg = "Tenant resolved successfully. correlation_id=abc-123"
        result = scrub_pii(msg)
        assert result == msg

    def test_multiple_pii_scrubbed_in_one_pass(self):
        msg = "User 123.456.789-09 with email test@test.com"
        result = scrub_pii(msg)
        assert "123.456.789-09" not in result
        assert "test@test.com" not in result

    def test_empty_string_unchanged(self):
        assert scrub_pii("") == ""

    def test_scrubber_is_idempotent(self):
        """Aplicar o scrubber duas vezes não deve alterar o resultado."""
        msg = "CPF: 123.456.789-09"
        once = scrub_pii(msg)
        twice = scrub_pii(once)
        assert once == twice
