# =============================================================================
# Archon-V — Admin API Schemas (LGPD-Compliant)
# File: api/v1/admin/schemas.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
CONTRATOS DA API ADMINISTRATIVA

SEGURANÇA DE ACESSO:
  Endpoints admin exigem header `X-Admin-Key` com chave de operação.
  Em produção: rotacionada via Secret Manager, escopos distintos por operação.
  Nunca exposta ao tenant — apenas ao operador (ISV).

LGPD — Transparência (Art. 6 VI):
  Todos os campos de dados pessoais são documentados com sua finalidade,
  base legal e se são obrigatórios ou opcionais.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, field_validator

from core.tenant.provisioner import PlanTier


TenantId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$", max_length=63),
]

EmailStr = Annotated[
    str,
    StringConstraints(pattern=r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", max_length=254),
]


# ---------------------------------------------------------------------------
# TENANT PROVISIONING
# ---------------------------------------------------------------------------

class TenantProvisionRequest(BaseModel):
    """
    Requisição de provisionamento de novo tenant.
    
    LGPD — Campos e suas bases legais:
      tenant_id:              Identificador técnico. Legítimo interesse (Art. 7 IX).
      plan_tier:              Necessário para billing. Execução de contrato (Art. 7 V).
      data_controller_name:   Obrigatório LGPD Art. 5 VI — identifica o controlador.
      dpo_contact_email:      Obrigatório LGPD Art. 41 — contato do Encarregado.
                              Pseudonimizado antes de armazenar.
    """
    model_config = {"frozen": True}

    tenant_id: TenantId = Field(
        ..., description="Slug único do tenant (DNS-safe, máx 63 chars)."
    )
    plan_tier: PlanTier = Field(
        ..., description="Plano comercial: STARTER | PROFESSIONAL | ENTERPRISE."
    )
    data_controller_name: Annotated[str, StringConstraints(max_length=256)] = Field(
        ...,
        description=(
            "Nome legal da empresa controladora dos dados. "
            "LGPD Art. 5 VI — identificação obrigatória do controlador."
        ),
    )
    dpo_contact_email: EmailStr = Field(
        ...,
        description=(
            "Email do DPO / Encarregado de Dados. "
            "LGPD Art. 41 — obrigatório para organizações que tratam dados em larga escala. "
            "Será pseudonimizado (SHA-256) antes de armazenar."
        ),
    )
    correlation_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")] = Field(
        ..., description="UUIDv4 de idempotência da operação de provisionamento."
    )


class TenantProvisionResponse(BaseModel):
    """Resposta de provisionamento. Campos sensíveis mascarados."""
    model_config = {"frozen": True}

    tenant_id: str
    plan_tier: str
    data_controller_name: str
    dpo_contact_hash: str = Field(
        ..., description="SHA-256 do email do DPO (pseudonimizado — LGPD Art. 12)."
    )
    kms_key_ring_name: str
    db_schema_identifier: str
    provisioned_at: str
    was_idempotent: bool
    audit_entry_id: str


class TenantSuspendRequest(BaseModel):
    model_config = {"frozen": True}

    reason: Annotated[str, StringConstraints(max_length=512)] = Field(
        ..., description="Motivo da suspensão (registrado no audit trail)."
    )
    correlation_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")]


class TenantEraseRequest(BaseModel):
    """
    LGPD Art. 18 VI — Solicitação de eliminação de dados.
    
    O campo `lgpd_confirmation` é obrigatório e deve ser exatamente
    "CONFIRMO_EXCLUSAO_LGPD" — evita exclusões acidentais.
    """
    model_config = {"frozen": True}

    lgpd_confirmation: str = Field(
        ...,
        description=(
            "Confirmação explícita. Deve ser exatamente: 'CONFIRMO_EXCLUSAO_LGPD'. "
            "Proteção contra deleção acidental de dados de produção."
        ),
    )
    correlation_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")]

    @field_validator("lgpd_confirmation")
    @classmethod
    def validate_confirmation(cls, v: str) -> str:
        if v != "CONFIRMO_EXCLUSAO_LGPD":
            raise ValueError(
                "lgpd_confirmation must be exactly 'CONFIRMO_EXCLUSAO_LGPD' to confirm data erasure."
            )
        return v


class TenantEraseResponse(BaseModel):
    model_config = {"frozen": True}

    tenant_id: str
    erased_at: str
    audit_entries_anonymized: int
    lgpd_article: str
    correlation_id: str


# ---------------------------------------------------------------------------
# POLICY RULESET MANAGEMENT
# ---------------------------------------------------------------------------

class PolicyRuleInput(BaseModel):
    """Definição de uma regra individual para um ruleset customizado."""
    model_config = {"frozen": True}

    rule_id: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2,10}-[A-Z]+-\d{3}$", max_length=32)] = Field(
        ...,
        description="ID da regra em formato CATEGORIA-TIPO-NUM. Ex: 'CUSTOM-PII-001'.",
    )
    rule_type: str = Field(..., description="SECRET_PATTERN | PII_PATTERN | FILE_PATH | CONTRACT_DRIFT")
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW")
    pattern: Annotated[str, StringConstraints(max_length=512)]
    description: Annotated[str, StringConstraints(max_length=512)]
    remediation_hint: Annotated[str, StringConstraints(max_length=512)] = ""
    lgpd_basis: Annotated[str, StringConstraints(max_length=256)] = Field(
        ..., description="Base legal LGPD para o tratamento deste dado. Ex: 'Art. 6 III — Necessidade'.",
    )


class PolicyRulesetCreateRequest(BaseModel):
    model_config = {"frozen": True}

    version: Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")] = Field(
        ..., description="SemVer do novo ruleset. Deve ser maior que a versão atual."
    )
    rules: list[PolicyRuleInput] = Field(
        ..., min_length=1, max_length=200,
        description="Lista de regras. Máximo 200 regras por ruleset."
    )
    correlation_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")]


class PolicyRulesetResponse(BaseModel):
    ruleset_id: str
    tenant_id: str
    version: str
    status: str
    rules_count: int
    created_at: str
    published_at: str | None = None


# ---------------------------------------------------------------------------
# AUDIT TRAIL RESPONSE
# ---------------------------------------------------------------------------

class AuditEntryResponse(BaseModel):
    entry_id: str
    tenant_id: str
    action: str
    actor_id_hash: str
    correlation_id: str
    timestamp_utc: str
    entry_hash: str


class AuditTrailResponse(BaseModel):
    tenant_id: str
    entries: list[AuditEntryResponse]
    chain_integrity_verified: bool
    total_entries: int


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION
# python -c "import ast; ast.parse(open('api/v1/admin/schemas.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
