# =============================================================================
# Archon-V — Immutable Versioned Policy Ruleset Engine
# File: core/policy/ruleset.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
MOTOR DE RULESETS — TRÍADE CIA (Integridade + Confidencialidade)

INVARIANTES:
  1. Rulesets são IMUTÁVEIS após publicação. Um ruleset v1.2.0 publicado nunca
     muda. Correções geram v1.2.1. (Zero Regression — contrato público.)
  2. Backward compatibility: uma regra nunca é deletada — apenas DEPRECATED.
     Clientes em v1.x.x continuam recebendo regras v1.x.x mesmo após v2.0.0.
  3. Rulesets são POR TENANT — cada empresa pode ter suas próprias regras
     além das regras do sistema (base rules).
  4. Regras do sistema (built-in) não podem ser sobrescritas por tenant,
     apenas complementadas.

LGPD — Finalidade e Necessidade (Art. 6 I e III):
  Cada regra documenta sua finalidade legal — por que estamos processando
  esse padrão de dado. Isso compõe o REAT (Registro de Atividades de Tratamento).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Final

from api.v1.gate.schemas import ViolationSeverity


class RulesetStatus(str, Enum):
    DRAFT      = "DRAFT"       # Em elaboração — não aplicado ainda
    PUBLISHED  = "PUBLISHED"   # Ativo — sendo aplicado no gate
    DEPRECATED = "DEPRECATED"  # Substituído por versão mais nova (nunca deletado)


class RuleType(str, Enum):
    SECRET_PATTERN = "SECRET_PATTERN"    # Regex que detecta segredos
    PII_PATTERN    = "PII_PATTERN"       # Regex que detecta PII (LGPD)
    FILE_PATH      = "FILE_PATH"         # Bloqueia arquivos por path (ex: *.env)
    CONTRACT_DRIFT = "CONTRACT_DRIFT"    # Detecta breaking changes de API


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """
    Regra individual de política. Imutável após criação.
    
    LGPD — Finalidade (Art. 6 I): campo `lgpd_basis` documenta a base legal
    para o processamento do padrão detectado.
    """
    rule_id: str                        # Ex: "SEC-AWS-002", "PII-CNPJ-BR-001"
    rule_type: RuleType
    severity: ViolationSeverity
    pattern: str                        # Regex string (compilada no scan)
    description: str                    # Descrição human-readable
    remediation_hint: str               # O que o dev deve fazer
    lgpd_basis: str                     # Base legal LGPD/GDPR para processar este dado
    compiled_pattern: re.Pattern | None = field(default=None, compare=False, hash=False)

    def __post_init__(self) -> None:
        # Valida e compila o padrão imediatamente
        try:
            object.__setattr__(self, "compiled_pattern", re.compile(self.pattern))
        except re.error as e:
            raise ValueError(f"Invalid regex pattern for rule {self.rule_id}: {e}") from e


@dataclass(frozen=True, slots=True)
class PolicyRuleset:
    """
    Conjunto versionado de regras. Imutável após publicação.
    
    SemVer:
      MAJOR — mudanças que alteram comportamento de BLOCK (breaking)
      MINOR — novas regras que adicionam WARN sem afetar BLOCK existente
      PATCH — correções de regex/descrição sem impacto funcional
    """
    ruleset_id: str
    tenant_id: str          # "SYSTEM" para regras built-in
    version: str            # SemVer: "1.2.3"
    status: RulesetStatus
    rules: tuple[PolicyRule, ...]
    created_at: str
    published_at: str | None
    deprecated_at: str | None
    created_by_hash: str    # SHA-256 do actor que criou (pseudonimização LGPD)


class PolicyRulesetStore:
    """
    Repositório de rulesets por tenant.
    
    PRODUÇÃO: substituir por PostgreSQL com schema por tenant.
    MVP: in-memory com isolamento por tenant_id.
    
    IMUTABILIDADE: dict nunca remove entradas — apenas adiciona novas versões.
    """

    def __init__(self) -> None:
        # {tenant_id: {ruleset_id: PolicyRuleset}}
        self._store: dict[str, dict[str, PolicyRuleset]] = {}

    def _tenant_store(self, tenant_id: str) -> dict[str, PolicyRuleset]:
        if tenant_id not in self._store:
            self._store[tenant_id] = {}
        return self._store[tenant_id]

    def create(
        self,
        *,
        tenant_id: str,
        version: str,
        rules: list[PolicyRule],
        created_by_hash: str,
    ) -> PolicyRuleset:
        """
        Cria um novo ruleset no status DRAFT.
        Valida SemVer e que version > versão mais recente do tenant.
        """
        self._validate_semver(version)
        self._validate_version_increment(tenant_id, version)

        ruleset = PolicyRuleset(
            ruleset_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            version=version,
            status=RulesetStatus.DRAFT,
            rules=tuple(rules),
            created_at=datetime.now(timezone.utc).isoformat(),
            published_at=None,
            deprecated_at=None,
            created_by_hash=created_by_hash,
        )
        self._tenant_store(tenant_id)[ruleset.ruleset_id] = ruleset
        return ruleset

    def publish(self, tenant_id: str, ruleset_id: str) -> PolicyRuleset:
        """
        Publica um DRAFT → PUBLISHED.
        Depreca automaticamente a versão PUBLISHED anterior.
        PUBLISHED → imutável para sempre.
        """
        store = self._tenant_store(tenant_id)
        ruleset = store.get(ruleset_id)
        if not ruleset:
            raise KeyError(f"Ruleset {ruleset_id} not found for tenant {tenant_id}")
        if ruleset.status != RulesetStatus.DRAFT:
            raise ValueError(f"Only DRAFT rulesets can be published. Current: {ruleset.status}")

        # Depreca versão anterior
        now = datetime.now(timezone.utc).isoformat()
        for rid, rs in store.items():
            if rs.status == RulesetStatus.PUBLISHED and rid != ruleset_id:
                object.__setattr__(rs, "status", RulesetStatus.DEPRECATED)
                object.__setattr__(rs, "deprecated_at", now)

        # Publica a nova versão (cria novo objeto imutável)
        published = PolicyRuleset(
            ruleset_id=ruleset.ruleset_id,
            tenant_id=ruleset.tenant_id,
            version=ruleset.version,
            status=RulesetStatus.PUBLISHED,
            rules=ruleset.rules,
            created_at=ruleset.created_at,
            published_at=now,
            deprecated_at=None,
            created_by_hash=ruleset.created_by_hash,
        )
        store[ruleset_id] = published
        return published

    def get_active(self, tenant_id: str) -> PolicyRuleset | None:
        """Retorna o ruleset PUBLISHED do tenant, ou None."""
        store = self._tenant_store(tenant_id)
        for rs in store.values():
            if rs.status == RulesetStatus.PUBLISHED:
                return rs
        return None

    def get_all(self, tenant_id: str) -> list[PolicyRuleset]:
        """Retorna todos os rulesets (incluindo DEPRECATED) — imutabilidade histórica."""
        return list(self._tenant_store(tenant_id).values())

    @staticmethod
    def _validate_semver(version: str) -> None:
        parts = version.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError(f"Invalid SemVer: '{version}'. Expected format: MAJOR.MINOR.PATCH")

    def _validate_version_increment(self, tenant_id: str, new_version: str) -> None:
        """Garante que a nova versão é maior que todas as existentes."""
        def to_tuple(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split("."))

        store = self._tenant_store(tenant_id)
        for rs in store.values():
            if to_tuple(new_version) <= to_tuple(rs.version):
                raise ValueError(
                    f"New version {new_version} must be greater than existing {rs.version}. "
                    "Additive-only — no version regression allowed."
                )


# Singleton
_ruleset_store = PolicyRulesetStore()


def get_ruleset_store() -> PolicyRulesetStore:
    return _ruleset_store


# ---------------------------------------------------------------------------
# REGRAS BUILT-IN DO SISTEMA (tenant_id="SYSTEM")
# ---------------------------------------------------------------------------

SYSTEM_RULES: Final[tuple[PolicyRule, ...]] = (
    PolicyRule(
        rule_id="SYS-PATH-ENV-001",
        rule_type=RuleType.FILE_PATH,
        severity=ViolationSeverity.CRITICAL,
        pattern=r"\.env$|\.env\.\w+$",
        description="Arquivo .env detectado no staging — nunca deve ser commitado.",
        remediation_hint="Adicione *.env ao .gitignore e use variáveis de ambiente seguras.",
        lgpd_basis="Necessidade (Art. 6 III) — prevenção de vazamento de credenciais de sistemas de produção.",
    ),
    PolicyRule(
        rule_id="SYS-PATH-KEY-001",
        rule_type=RuleType.FILE_PATH,
        severity=ViolationSeverity.CRITICAL,
        pattern=r"\.(pem|key|p12|pfx|jks)$",
        description="Arquivo de chave criptográfica detectado no staging.",
        remediation_hint="Remova o arquivo do staging. Use Secret Manager ou KMS.",
        lgpd_basis="Necessidade (Art. 6 III) — proteção de material criptográfico.",
    ),
)

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION
# python -c "import ast; ast.parse(open('core/policy/ruleset.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
