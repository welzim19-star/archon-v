# =============================================================================
# Archon-V — Policy Enforcement Engine (Verdict Aggregator)
# File: core/interceptor/pee.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
POLICY ENFORCEMENT ENGINE (PEE)

Orquestra a varredura e consolida o veredito final.
Regras de agregação:
1. Qualquer violação CRITICAL (Secrets ou PII) → BLOCK imediato.
2. O parser NUNCA armazena os diffs originais na memória além do escopo da request.
"""

from __future__ import annotations

import logging
import uuid
from typing import Iterator

from api.v1.gate.schemas import (
    PolicyVerdict,
    PolicyViolation,
    StagedFileDiff,
    ViolationSeverity,
)
from core.interceptor.pii import PIIDetector, PIIViolation
from core.interceptor.secrets import SecretScanner, SecretViolation

logger = logging.getLogger("archon_v.pee")


class PolicyEnforcementEngine:
    """
    Agregador O(1) amortizado para os motores de inspeção.
    """

    def __init__(self) -> None:
        self.secret_scanner = SecretScanner()
        self.pii_detector = PIIDetector()
        # Contract Drift Validator entraria aqui no futuro

    def evaluate_file(self, file_diff: StagedFileDiff, raw_diff_content: str) -> Iterator[PolicyViolation]:
        """
        Escaneia um único arquivo e produz um generator de violações.
        O(n) atrelado ao tamanho do `raw_diff_content`, mas com teto rígido no motor.
        """
        # 1. Scan por Segredos
        for sec_viol in self.secret_scanner.scan(raw_diff_content):
            yield PolicyViolation(
                violation_id=str(uuid.uuid4()),
                severity=ViolationSeverity.CRITICAL,
                rule_id=sec_viol.rule_id,
                file_path=file_diff.file_path,
                description=sec_viol.description,
                remediation_hint="Remova o segredo do código e faça rotação (rotate) da chave comprometida.",
            )

        # 2. Scan por PII
        for pii_viol in self.pii_detector.scan(raw_diff_content):
            yield PolicyViolation(
                violation_id=str(uuid.uuid4()),
                severity=ViolationSeverity.CRITICAL, # PII é sempre critical em contexto enterprise
                rule_id=pii_viol.rule_id,
                file_path=file_diff.file_path,
                description=pii_viol.description,
                remediation_hint="Utilize dados sintéticos (fakes) ou remova a informação sensível do diff.",
            )

    def aggregate_verdict(self, violations: list[PolicyViolation]) -> PolicyVerdict:
        """
        Agrega o veredito com base na severidade máxima encontrada.
        O(v) onde v é o número de violações.
        """
        if not violations:
            return PolicyVerdict.ALLOW

        for v in violations:
            if v.severity == ViolationSeverity.CRITICAL:
                return PolicyVerdict.BLOCK
            
        # Para o MVP, trataremos a existência de qualquer violation não-CRITICAL como WARN
        return PolicyVerdict.WARN

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/interceptor/pee.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
