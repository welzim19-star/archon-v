# =============================================================================
# Archon-V — Unit Tests: PII Detector
# File: tests/unit/test_pii.py
# =============================================================================
import pytest
from core.interceptor.pii import PIIDetector


@pytest.fixture
def detector() -> PIIDetector:
    return PIIDetector()


class TestPIIDetectorBrazil:
    """LGPD: Dados pessoais brasileiros."""

    def test_detects_cpf_formatted(self, detector):
        diff = "cpf = '123.456.789-09'"
        violations = list(detector.scan(diff))
        assert any(v.rule_id == "PII-CPF-BR-001" for v in violations)

    def test_cpf_without_mask_not_flagged(self, detector):
        """CPF sem formatação (12345678909) — não flagamos para evitar FP em números."""
        diff = "user_id = 12345678909"
        violations = list(detector.scan(diff))
        assert not any(v.rule_id == "PII-CPF-BR-001" for v in violations)


class TestPIIDetectorEmail:
    """Emails hardcoded no código (LGPD: dado pessoal identificável)."""

    def test_detects_email_in_code(self, detector):
        diff = 'default_contact = "joao.silva@empresa.com.br"'
        violations = list(detector.scan(diff))
        assert any(v.rule_id == "PII-EMAIL-001" for v in violations)

    def test_detects_email_in_comment(self, detector):
        diff = "# Contato: dev@acme.corp"
        violations = list(detector.scan(diff))
        assert any(v.rule_id == "PII-EMAIL-001" for v in violations)


class TestPIIDetectorCreditCard:
    """PCI-DSS: Números de cartão de crédito."""

    def test_detects_visa_card(self, detector):
        diff = "card = '4532015112830366'"
        violations = list(detector.scan(diff))
        assert any(v.rule_id == "PII-CREDIT-CARD-001" for v in violations)

    def test_detects_mastercard(self, detector):
        diff = "pan = 5425233430109903"
        violations = list(detector.scan(diff))
        assert any(v.rule_id == "PII-CREDIT-CARD-001" for v in violations)

    def test_detects_amex(self, detector):
        diff = "card_number = 374251018720955"
        violations = list(detector.scan(diff))
        assert any(v.rule_id == "PII-CREDIT-CARD-001" for v in violations)


class TestPIIDetectorCleanCode:
    """Código limpo sem PII."""

    def test_clean_function_no_violations(self, detector):
        diff = "def process_payment(amount: float, currency: str) -> bool:\n    return True\n"
        violations = list(detector.scan(diff))
        assert violations == []

    def test_math_numbers_not_flagged(self, detector):
        diff = "TAX_RATE = 0.0625\nMAX_RETRIES = 3"
        violations = list(detector.scan(diff))
        assert violations == []

    def test_empty_diff_clean(self, detector):
        assert list(detector.scan("")) == []


class TestPIIReturnedData:
    """Garante que o dado real não é retornado nas violations."""

    def test_violation_does_not_contain_raw_cpf(self, detector):
        real_cpf = "123.456.789-09"
        diff = f"cpf = '{real_cpf}'"
        violations = list(detector.scan(diff))
        for v in violations:
            assert real_cpf not in v.description
            assert real_cpf not in v.rule_id

    def test_violation_does_not_contain_raw_email(self, detector):
        real_email = "joao.silva@empresa.com.br"
        diff = f'email = "{real_email}"'
        violations = list(detector.scan(diff))
        for v in violations:
            assert real_email not in v.description
