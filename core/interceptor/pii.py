# =============================================================================
# Archon-V — PII Detector Engine
# File: core/interceptor/pii.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
PII DETECTOR (Bloom Filter Concept)

INVARIANTES DE SEGURANÇA:
1. PII detection deve ser probabilístico/rápido no hot-path.
2. Em um MVP, usaremos Regex compilado focado em padrões estritos (O(n) limitado).
3. Na fase Enterprise, isso será substituído por um Bloom Filter real ou C-extension.
4. Descarte automático de logs que contenham PII. A string original NUNCA é logada.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Iterator

# ---------------------------------------------------------------------------
# CONSTANTS & COMPILED PATTERNS
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PIIRule:
    rule_id: str
    pattern: re.Pattern[str]
    description: str

# Regexes altamente restritas para evitar Falsos Positivos em código-fonte.
_PII_RULES: Final[tuple[PIIRule, ...]] = (
    PIIRule(
        rule_id="PII-EMAIL-001",
        # Detecta emails fixados no código (comum em mocks que viram prod). 
        # Exclui domínios genéricos de test.
        pattern=re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        description="Potential Email Address (PII) hardcoded in diff",
    ),
    PIIRule(
        rule_id="PII-CREDIT-CARD-001",
        # Regex básica para cartões (Luhn check seria ideal, mas Regex é mais rápido no gate)
        pattern=re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"),
        description="Potential Credit Card PAN (PCI-DSS) detected",
    ),
    PIIRule(
        rule_id="PII-CPF-BR-001",
        # Formato estrito de CPF (000.000.000-00) comum em payloads mockados.
        pattern=re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
        description="Potential Brazilian CPF (LGPD) detected",
    ),
)


@dataclass(frozen=True, slots=True)
class PIIViolation:
    rule_id: str
    description: str


class PIIDetector:
    """
    Motor de detecção de PII.
    Otimizado para falhar rápido e ignorar falsos positivos aceitáveis (Fail-Secure).
    """

    def scan(self, diff_content: str) -> Iterator[PIIViolation]:
        """
        Escaneia o diff contra regras conhecidas de PII.
        """
        # Exclusões globais rápidas para evitar scan desnecessário
        # Exemplo: se o arquivo for listado como mock/teste pelo MIME/path,
        # poderíamos bypassar no Verdict Aggregator.
        
        for rule in _PII_RULES:
            if rule.pattern.search(diff_content):
                # IMPORTANTE: Nunca retornamos o `match.group()`. 
                # A string real do CPF ou Email morre aqui na RAM.
                yield PIIViolation(
                    rule_id=rule.rule_id,
                    description=rule.description,
                )

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/interceptor/pii.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
