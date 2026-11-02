# =============================================================================
# Archon-V — Admin API Router
# File: api/v1/admin/router.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
ROTAS ADMINISTRATIVAS — ACESSO RESTRITO AO OPERADOR (ISV)

AUTENTICAÇÃO DUPLA:
  1. TenantAuthMiddleware (Bearer JWT) — já executado pelo middleware global
  2. X-Admin-Key header — chave de operação rotacionada via Secret Manager
     Nenhum tenant tem acesso a estes endpoints — scope separado.

TRÍADE CIA:
  Confidencialidade: X-Admin-Key + JWT duplo. Respostas mascaradas.
  Integridade:       Toda mutação registrada no audit trail SHA-256.
  Disponibilidade:   Rate limiting separado para admin (não compete com gate).
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from api.v1.admin.schemas import (
    AuditEntryResponse,
    AuditTrailResponse,
    PolicyRuleInput,
    PolicyRulesetCreateRequest,
    PolicyRulesetResponse,
    TenantEraseRequest,
    TenantEraseResponse,
    TenantProvisionRequest,
    TenantProvisionResponse,
    TenantSuspendRequest,
)
from core.audit.trail import AuditAction, AuditTrailManager, get_audit_manager
from core.policy.ruleset import (
    PolicyRule,
    PolicyRulesetStore,
    RuleType,
    get_ruleset_store,
)
from core.tenant.provisioner import PlanTier, TenantProvisioner, get_provisioner
from api.v1.gate.schemas import ViolationSeverity

logger = logging.getLogger("archon_v.admin_router")

router = APIRouter(prefix="/v1/admin", tags=["Admin"])

# ---------------------------------------------------------------------------
# ADMIN KEY GUARD — Segunda camada de autenticação
# ---------------------------------------------------------------------------

_ADMIN_KEY_ENV_VAR = "ARCHON_ADMIN_KEY"


def _verify_admin_key(x_admin_key: str | None = Header(default=None)) -> None:
    """
    Dependência FastAPI: verifica X-Admin-Key.
    Fail-secure: qualquer ausência ou mismatch → 403 imediato.
    Timing-safe: comparação em tempo constante.
    """
    import hmac
    expected = os.environ.get(_ADMIN_KEY_ENV_VAR, "dev-admin-key-change-in-production")
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail={"error_code": "ERR_ADMIN_UNAUTHORIZED"})


AdminKeyDep = Depends(_verify_admin_key)


def _masked_error(correlation_id: str, code: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error_code": code, "correlation_id": correlation_id})


# ---------------------------------------------------------------------------
# TENANT MANAGEMENT
# ---------------------------------------------------------------------------

@router.post(
    "/tenants",
    response_model=TenantProvisionResponse,
    status_code=201,
    dependencies=[AdminKeyDep],
    summary="Provisionar novo tenant (idempotente)",
)
async def provision_tenant(
    body: TenantProvisionRequest,
    request: Request,
    provisioner: Annotated[TenantProvisioner, Depends(get_provisioner)],
) -> TenantProvisionResponse:
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")

    result = provisioner.provision(
        tenant_id=body.tenant_id,
        plan_tier=PlanTier(body.plan_tier),
        data_controller_name=body.data_controller_name,
        dpo_contact_email=body.dpo_contact_email,
        actor_id=actor_id,
        correlation_id=body.correlation_id,
    )
    r = result.tenant_record
    return TenantProvisionResponse(
        tenant_id=r.tenant_id,
        plan_tier=r.plan_tier.value,
        data_controller_name=r.data_controller_name,
        dpo_contact_hash=r.dpo_contact_hash,
        kms_key_ring_name=r.kms_key_ring_name,
        db_schema_identifier=r.db_schema_identifier,
        provisioned_at=r.provisioned_at,
        was_idempotent=result.was_idempotent,
        audit_entry_id=result.audit_entry_id,
    )


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantProvisionResponse,
    dependencies=[AdminKeyDep],
    summary="Obter informações do tenant (mascarado)",
)
async def get_tenant(
    tenant_id: str,
    request: Request,
    provisioner: Annotated[TenantProvisioner, Depends(get_provisioner)],
    audit: Annotated[AuditTrailManager, Depends(get_audit_manager)],
) -> TenantProvisionResponse | JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")

    record = provisioner.get(tenant_id)
    if not record:
        return _masked_error(correlation_id, "ERR_TENANT_NOT_FOUND", 404)

    audit.record(
        tenant_id=tenant_id,
        action=AuditAction.ADMIN_ACCESS,
        actor_id=actor_id,
        correlation_id=correlation_id,
        metadata={"operation": "GET_TENANT"},
    )
    return TenantProvisionResponse(
        tenant_id=record.tenant_id,
        plan_tier=record.plan_tier.value,
        data_controller_name=record.data_controller_name,
        dpo_contact_hash=record.dpo_contact_hash,
        kms_key_ring_name=record.kms_key_ring_name,
        db_schema_identifier=record.db_schema_identifier,
        provisioned_at=record.provisioned_at,
        was_idempotent=True,
        audit_entry_id="",
    )


@router.post(
    "/tenants/{tenant_id}/suspend",
    status_code=200,
    dependencies=[AdminKeyDep],
    summary="Suspender tenant",
)
async def suspend_tenant(
    tenant_id: str,
    body: TenantSuspendRequest,
    request: Request,
    provisioner: Annotated[TenantProvisioner, Depends(get_provisioner)],
) -> dict:
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")
    try:
        provisioner.suspend(
            tenant_id=tenant_id,
            reason=body.reason,
            actor_id=actor_id,
            correlation_id=body.correlation_id,
        )
    except KeyError:
        return _masked_error(correlation_id, "ERR_TENANT_NOT_FOUND", 404)
    return {"status": "suspended", "tenant_id": tenant_id, "correlation_id": correlation_id}


@router.delete(
    "/tenants/{tenant_id}",
    response_model=TenantEraseResponse,
    dependencies=[AdminKeyDep],
    summary="LGPD Art. 18 VI — Eliminação de dados do tenant",
)
async def erase_tenant(
    tenant_id: str,
    body: TenantEraseRequest,
    request: Request,
    provisioner: Annotated[TenantProvisioner, Depends(get_provisioner)],
) -> TenantEraseResponse | JSONResponse:
    """
    Elimina todos os dados pessoais do tenant (LGPD Art. 18 VI).
    Requer confirmação explícita: lgpd_confirmation = 'CONFIRMO_EXCLUSAO_LGPD'.
    Audit trail é ANONIMIZADO (não deletado) — compliance Art. 16 I.
    """
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")
    report = provisioner.erase(
        tenant_id=tenant_id,
        actor_id=actor_id,
        correlation_id=body.correlation_id,
    )
    return TenantEraseResponse(
        tenant_id=report["tenant_id"],
        erased_at=report["erased_at"],
        audit_entries_anonymized=report["audit_entries_anonymized"],
        lgpd_article=report["lgpd_article"],
        correlation_id=report["correlation_id"],
    )


# ---------------------------------------------------------------------------
# POLICY RULESET MANAGEMENT
# ---------------------------------------------------------------------------

@router.post(
    "/tenants/{tenant_id}/rulesets",
    response_model=PolicyRulesetResponse,
    status_code=201,
    dependencies=[AdminKeyDep],
    summary="Criar novo ruleset de política (DRAFT)",
)
async def create_ruleset(
    tenant_id: str,
    body: PolicyRulesetCreateRequest,
    request: Request,
    store: Annotated[PolicyRulesetStore, Depends(get_ruleset_store)],
    audit: Annotated[AuditTrailManager, Depends(get_audit_manager)],
) -> PolicyRulesetResponse | JSONResponse:
    import hashlib
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")
    actor_hash = hashlib.sha256(actor_id.encode()).hexdigest()

    try:
        rules = [
            PolicyRule(
                rule_id=r.rule_id,
                rule_type=RuleType(r.rule_type),
                severity=ViolationSeverity(r.severity),
                pattern=r.pattern,
                description=r.description,
                remediation_hint=r.remediation_hint,
                lgpd_basis=r.lgpd_basis,
            )
            for r in body.rules
        ]
        ruleset = store.create(
            tenant_id=tenant_id,
            version=body.version,
            rules=rules,
            created_by_hash=actor_hash,
        )
    except (ValueError, re.error if False else ValueError) as e:
        return _masked_error(correlation_id, "ERR_RULESET_INVALID", 422)

    audit.record(
        tenant_id=tenant_id,
        action=AuditAction.POLICY_RULESET_CREATED,
        actor_id=actor_id,
        correlation_id=body.correlation_id,
        metadata={"version": body.version, "rules_count": len(rules)},
    )
    return PolicyRulesetResponse(
        ruleset_id=ruleset.ruleset_id,
        tenant_id=ruleset.tenant_id,
        version=ruleset.version,
        status=ruleset.status.value,
        rules_count=len(ruleset.rules),
        created_at=ruleset.created_at,
        published_at=ruleset.published_at,
    )


@router.post(
    "/tenants/{tenant_id}/rulesets/{ruleset_id}/publish",
    response_model=PolicyRulesetResponse,
    dependencies=[AdminKeyDep],
    summary="Publicar ruleset DRAFT → PUBLISHED (depreca versão anterior)",
)
async def publish_ruleset(
    tenant_id: str,
    ruleset_id: str,
    request: Request,
    store: Annotated[PolicyRulesetStore, Depends(get_ruleset_store)],
    audit: Annotated[AuditTrailManager, Depends(get_audit_manager)],
) -> PolicyRulesetResponse | JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")
    try:
        ruleset = store.publish(tenant_id, ruleset_id)
    except (KeyError, ValueError) as e:
        return _masked_error(correlation_id, "ERR_RULESET_PUBLISH_FAILED", 422)
    audit.record(
        tenant_id=tenant_id,
        action=AuditAction.POLICY_RULESET_CREATED,
        actor_id=actor_id,
        correlation_id=correlation_id,
        metadata={"ruleset_id": ruleset_id, "version": ruleset.version, "status": "PUBLISHED"},
    )
    return PolicyRulesetResponse(
        ruleset_id=ruleset.ruleset_id,
        tenant_id=ruleset.tenant_id,
        version=ruleset.version,
        status=ruleset.status.value,
        rules_count=len(ruleset.rules),
        created_at=ruleset.created_at,
        published_at=ruleset.published_at,
    )


# ---------------------------------------------------------------------------
# AUDIT TRAIL
# ---------------------------------------------------------------------------

@router.get(
    "/tenants/{tenant_id}/audit-trail",
    response_model=AuditTrailResponse,
    dependencies=[AdminKeyDep],
    summary="LGPD REAT — Registro de Atividades de Tratamento do tenant",
)
async def get_audit_trail(
    tenant_id: str,
    request: Request,
    audit: Annotated[AuditTrailManager, Depends(get_audit_manager)],
    limit: int = 100,
    offset: int = 0,
) -> AuditTrailResponse:
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    actor_id = getattr(request.state, "actor_id", "system")

    entries_raw = audit.get_entries(tenant_id, limit=limit, offset=offset)
    chain_ok = audit.verify_tenant_chain(tenant_id)

    audit.record(
        tenant_id=tenant_id,
        action=AuditAction.ADMIN_ACCESS,
        actor_id=actor_id,
        correlation_id=correlation_id,
        metadata={"operation": "GET_AUDIT_TRAIL"},
    )

    return AuditTrailResponse(
        tenant_id=tenant_id,
        entries=[AuditEntryResponse(**e) for e in entries_raw],
        chain_integrity_verified=chain_ok,
        total_entries=len(entries_raw),
    )


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION
# python -c "import ast; ast.parse(open('api/v1/admin/router.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
