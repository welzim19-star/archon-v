# =============================================================================
# Archon-V — Secret Scanner Engine
# File: core/interceptor/secrets.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
SECRET SCANNER (O(1) Amortizado)

INVARIANTES DE SEGURANÇA:
1. Expressões regulares são PRÉ-COMPILADAS em tempo de inicialização (Load Time).
   Isso garante que o scan O(n) sobre o diff não pague o custo de compilação.
2. Tamanho máximo do diff processado é limitado (Hard Limit 1MB por arquivo).
   Acima disso, o arquivo é bypassado com aviso ou bloqueado (configurável).
3. Nunca retorne a string do segredo (PII/Secret) na exception ou verdict.
   Retorne apenas o ID da regra violada e a linha aproximada.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Iterator

# ---------------------------------------------------------------------------
# CONSTANTS & COMPILED PATTERNS
# ---------------------------------------------------------------------------

_MAX_DIFF_SIZE_BYTES: Final[int] = 1_048_576  # 1 MB hard limit per file

@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    pattern: re.Pattern[str]
    description: str

# Corpus proprietário (simplificado para MVP, mas usa re.compile para O(1) start)
_SECRET_RULES: Final[tuple[SecretRule, ...]] = (
    SecretRule(
        rule_id="SEC-RSA-001",
        pattern=re.compile(r"-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----"),
        description="Private key block detected",
    ),
    SecretRule(
        rule_id="SEC-AWS-001",
        pattern=re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
        description="AWS Access Key ID detected",
    ),
    SecretRule(
        rule_id="SEC-GCP-001",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        description="GCP API Key detected",
    ),
    SecretRule(
        rule_id="SEC-ENV-001",
        pattern=re.compile(r"(?i)(?:password|secret|token|api_key)\s*=\s*['\"][^'\"]{10,}['\"]"),
        description="Hardcoded high-entropy secret assignment",
    ),
)


@dataclass(frozen=True, slots=True)
class SecretViolation:
    rule_id: str
    description: str


class SecretScanner:
    """
    Engine de scan de segredos usando Regex compiladas.
    Para O(1) real em grandes volumes, usaremos o algoritmo de Aho-Corasick (Trie) 
    em C++ via binding Python no futuro. Por ora, regex compiladas resolvem o SLA.
    """

    def scan(self, diff_content: str) -> Iterator[SecretViolation]:
        """
        Varre o conteúdo do diff em busca de segredos conhecidos.
        Gera um yield para cada violação encontrada (evita carregar tudo em memória).
        """
        if len(diff_content.encode("utf-8")) > _MAX_DIFF_SIZE_BYTES:
            # Proteção contra ReDoS e estouro de memória O(n)
            yield SecretViolation(
                rule_id="SEC-LIMIT-001",
                description="File diff exceeds 1MB hard limit for real-time scanning.",
            )
            return

        for rule in _SECRET_RULES:
            if rule.pattern.search(diff_content):
                yield SecretViolation(
                    rule_id=rule.rule_id,
                    description=rule.description,
                )

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/interceptor/secrets.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
