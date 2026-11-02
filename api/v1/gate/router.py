# =============================================================================
# Archon-V — Pre-Flight Gate Router
# File: api/v1/gate/router.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
ENDPOINT: POST /v1/gate/pre-flight-check

Pipeline de execução (em ordem, fail-secure em qualquer etapa):
  1. Middleware de autenticação já executou (tenant_id e correlation_id no state).
  2. Cross-check: tenant_id do header vs tenant_id do body.
  3. Cache de idempotência: se correlation_id já foi processado, retorna cached.
  4. Resolver de Tenant KMS: valida BYOK e obtém engine de DB isolado.
  5. Policy Enforcement Engine: varre cada arquivo do diff.
  6. Agregar veredito e retornar resposta.
  7. Armazenar resultado no cache de idempotência.

NOTA SOBRE O DIFF CONTENT:
  O schema original só trafega o SHA-256 do diff (por design O(1) de payload).
  Para que o PEE possa escanear, o cliente DEVE enviar também o mapa de conteúdo
  no campo `diff_contents` (extensão aditiva ao contrato base). Isso é documentado
  e não quebra retrocompatibilidade — clientes antigos simplesmente não serão
  varridos por conteúdo (receberão veredito WARN com aviso de missing content).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api.v1.gate.schemas import (
    ErrorResponse,
    PolicyVerdict,
    PolicyViolation,
    PreFlightCheckRequest,
    PreFlightCheckResponse,
    ViolationSeverity,
)
from core.cache.idempotency import IdempotencyCache, get_idempotency_cache
from core.interceptor.pee import PolicyEnforcementEngine
from core.tenant.resolver import TenantResolutionFailure, TenantResolver

logger = logging.getLogger("archon_v.gate_router")

router = APIRouter(prefix="/v1/gate", tags=["Gate"])

# ---------------------------------------------------------------------------
# EXTENDED REQUEST MODEL (Aditivo — não quebra contrato base)
# ---------------------------------------------------------------------------

class PreFlightCheckFullRequest(BaseModel):
    """
    Extensão aditiva do contrato base que inclui o conteúdo real dos diffs
    para varredura pelo PEE. O campo `diff_contents` é OPCIONAL.
    Se ausente, a varredura de conteúdo é pulada e o veredito inclui WARN.
    """
    model_config = {"frozen": True}

    gate_request: PreFlightCheckRequest
    diff_contents: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Mapa de {file_path: raw_diff_content} para varredura de conteúdo. "
            "MÁXIMO de 500 entradas (alinhado com o teto do gate_request.staged_files). "
            "Conteúdo por arquivo: máximo 1MB (enforcement no SecretScanner)."
        ),
        max_length=500,
    )


# ---------------------------------------------------------------------------
# DEPENDÊNCIAS
# ---------------------------------------------------------------------------

def get_pee() -> PolicyEnforcementEngine:
    """FastAPI dependency — singleton do Policy Enforcement Engine."""
    return PolicyEnforcementEngine()


def get_tenant_resolver(request: Request) -> TenantResolver:
    """FastAPI dependency — pega o resolver do app state."""
    return request.app.state.tenant_resolver


# ---------------------------------------------------------------------------
# HELPER: Mascarar resposta de erro
# ---------------------------------------------------------------------------

def _error_json(correlation_id: str, error_code: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            error_code=error_code,
            correlation_id=correlation_id,
        ).model_dump(),
    )


# ---------------------------------------------------------------------------
# ENDPOINT PRINCIPAL
# ---------------------------------------------------------------------------

@router.post(
    "/pre-flight-check",
    response_model=PreFlightCheckResponse,
    responses={
        200: {"description": "Veredito emitido (ALLOW, BLOCK, WARN, REDACT)"},
        401: {"model": ErrorResponse, "description": "Não autenticado"},
        403: {"model": ErrorResponse, "description": "Tenant claim inválido ou mismatch"},
        422: {"description": "Payload inválido (Pydantic V2 validation error)"},
        503: {"model": ErrorResponse, "description": "Falha de resolução de tenant (fail-secure)"},
    },
    summary="Pre-Flight Security Gate Check",
    description=(
        "Intercepta um conjunto de arquivos staged no git e emite um veredito "
        "de segurança antes do commit ser persistido. "
        "Idempotente via X-Correlation-Id (TTL 5 min)."
    ),
)
async def pre_flight_check(
    payload: PreFlightCheckFullRequest,
    request: Request,
    cache: Annotated[IdempotencyCache, Depends(get_idempotency_cache)],
    pee: Annotated[PolicyEnforcementEngine, Depends(get_pee)],
    resolver: Annotated[TenantResolver, Depends(get_tenant_resolver)],
) -> PreFlightCheckResponse | JSONResponse:
    """
    Handler principal do gate de segurança.
    """
    gate_req = payload.gate_request
    correlation_id = request.state.correlation_id
    tenant_id_from_middleware = request.state.tenant_id

    # ------------------------------------------------------------------
    # PASSO 1: Cross-check tenant_id (middleware vs body)
    # ------------------------------------------------------------------
    if gate_req.tenant_id != tenant_id_from_middleware:
        logger.warning(
            "Tenant ID mismatch — body vs X-Tenant-Claim.",
            extra={"correlation_id": correlation_id},
        )
        return _error_json(correlation_id, "ERR_CLAIM_MISMATCH", 403)

    # ------------------------------------------------------------------
    # PASSO 2: Cache de idempotência
    # ------------------------------------------------------------------
    cached = cache.get(tenant_id_from_middleware, gate_req.correlation_id)
    if cached is not None:
        logger.info(
            "Cache hit — returning idempotent response.",
            extra={"correlation_id": correlation_id},
        )
        cached["cache_hit"] = True
        return PreFlightCheckResponse(**cached)

    # ------------------------------------------------------------------
    # PASSO 3: Resolver de Tenant KMS (Fail-Secure)
    # ------------------------------------------------------------------
    try:
        # MVP: usamos bytes stub para o claim. Em produção: passar JWT raw bytes.
        tenant_ctx, _engine = resolver.resolve(
            tenant_id=gate_req.tenant_id,
            raw_claim_bytes=gate_req.tenant_id.encode(),  # Produção: JWT raw bytes
            claim_hmac_tag=hashlib.sha256(gate_req.tenant_id.encode()).digest(),  # Produção: tag do header
            correlation_id=correlation_id,
        )
    except TenantResolutionFailure as exc:
        logger.error(
            "Tenant resolution failed — dropping request.",
            extra={"correlation_id": correlation_id},
        )
        return _error_json(correlation_id, exc.error_code, 503)

    # ------------------------------------------------------------------
    # PASSO 4: Policy Enforcement Engine
    # ------------------------------------------------------------------
    all_violations: list[PolicyViolation] = []

    for staged_file in gate_req.git_context.staged_files:
        raw_content = payload.diff_contents.get(staged_file.file_path, "")

        if not raw_content:
            # Diff content não enviado — emitir WARN de auditoria
            all_violations.append(
                PolicyViolation(
                    violation_id=str(uuid.uuid4()),
                    severity=ViolationSeverity.LOW,
                    rule_id="AUDIT-CONTENT-MISSING-001",
                    file_path=staged_file.file_path,
                    description="Diff content not provided — content scan skipped for this file.",
                    remediation_hint="Envie o conteúdo do diff no campo `diff_contents` para varredura completa.",
                )
            )
            continue

        # Integridade: verificar SHA-256 do conteúdo enviado
        computed_sha = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        if computed_sha != staged_file.diff_content_sha256:
            logger.warning(
                "Diff content SHA-256 mismatch — possible tampering.",
                extra={"correlation_id": correlation_id, "file": staged_file.file_path},
            )
            all_violations.append(
                PolicyViolation(
                    violation_id=str(uuid.uuid4()),
                    severity=ViolationSeverity.HIGH,
                    rule_id="SEC-INTEGRITY-001",
                    file_path=staged_file.file_path,
                    description="Diff content SHA-256 mismatch — content integrity check failed.",
                    remediation_hint="Verifique se o conteúdo do diff não foi alterado em trânsito.",
                )
            )
            continue

        # Scan pelo PEE
        for violation in pee.evaluate_file(staged_file, raw_content):
            all_violations.append(violation)

    # ------------------------------------------------------------------
    # PASSO 5: Agregar veredito
    # ------------------------------------------------------------------
    verdict = pee.aggregate_verdict(all_violations)

    # ------------------------------------------------------------------
    # PASSO 6: Construir resposta
    # ------------------------------------------------------------------
    response_data = PreFlightCheckResponse(
        correlation_id=gate_req.correlation_id,
        tenant_id=gate_req.tenant_id,
        verdict=verdict,
        violations=all_violations,
        evaluated_policy_version="1.0.0",
        evaluated_at_utc=datetime.now(timezone.utc),
        cache_hit=False,
    )

    logger.info(
        "Pre-flight check completed.",
        extra={
            "correlation_id": correlation_id,
            "verdict": verdict.value,
            "violations_count": len(all_violations),
            "tenant_id": gate_req.tenant_id,
        },
    )

    # ------------------------------------------------------------------
    # PASSO 7: Armazenar no cache de idempotência
    # ------------------------------------------------------------------
    cache.set(
        tenant_id_from_middleware,
        gate_req.correlation_id,
        response_data.model_dump(mode="json"),
    )

    return response_data

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('api/v1/gate/router.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
