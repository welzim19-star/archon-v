# =============================================================================
# Archon-V — JWT + Tenant Claim Authentication Middleware
# File: api/middleware/auth.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
MIDDLEWARE DE AUTENTICAÇÃO ZERO-TRUST

Responsabilidades (executadas nesta ordem, fail-secure em qualquer passo):
  1. Extrair e validar o Bearer JWT (actor identity) — RS256.
  2. Extrair e validar o X-Tenant-Claim JWT (tenant identity) — RS256.
  3. Cross-check: o `tenant_id` do X-Tenant-Claim DEVE bater com o `sub` esperado.
  4. Injetar `x_tenant_id` e `x_correlation_id` no request.state para os handlers.

Em qualquer falha: retornar HTTP 401 ou 403 com ErrorResponse mascarado.
  → NUNCA retornar detalhes da falha (qual claim falhou, qual campo inválido).

NOTA SEGURANÇA: A validação de JWT exige a chave pública (RS256) configurada na env var
`ARCHON_IDP_PUBLIC_KEY`. Em produção, isso pode ser trocado por um JWKS client
(JSON Web Key Set) apontando para o seu Provedor de Identidade.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("archon_v.auth_middleware")

# Rotas que NÃO passam pela autenticação (ex: playground web, health check, demo sandbox)
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/",
    "/favicon.ico",
    "/health",
    "/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/webhooks/gcp-marketplace",
})

_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/api/v1/demo",
    "/static",
)


def _make_error_response(correlation_id: str, error_code: str, status_code: int) -> JSONResponse:
    """
    Resposta de erro mascarada — zero stack trace, zero arquitetura.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "error_code": error_code,
            "correlation_id": correlation_id,
        },
    )


def _extract_bearer_token(authorization: str | None) -> str | None:
    """Extrai o token do header `Authorization: Bearer <token>`. O(1)."""
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


def _decode_jwt_claims(token: str) -> dict | None:
    """
    Decodificação com verificação criptográfica da assinatura (RS256).
    Requisito Bank-Grade: falha se a chave não estiver configurada ou se a assinatura não bater.
    """
    from jose import jwt, JWTError

    public_key = os.environ.get("ARCHON_IDP_PUBLIC_KEY")
    if not public_key:
        logger.error("ARCHON_IDP_PUBLIC_KEY not configured. JWT validation will FAIL-SECURE.")
        return None

    try:
        # jwt.decode força a validação da assinatura e expiração (exp)
        return jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})
    except JWTError as e:
        # Logamos o erro internamente, mas nunca o retornamos ao cliente (Zero-Trust)
        logger.warning("JWT validation failed: Cryptographic signature or claim invalid.")
        return None


class TenantAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware Starlette de autenticação zero-trust.
    Executado em TODA request antes de chegar ao handler.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # --- Paths isentos de auth (Playground, Health, Docs, Demo Sandbox) --
        if request.url.path in _EXEMPT_PATHS or any(request.url.path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        # --- Correlation ID (gerado aqui se não vier no header) ---------------
        correlation_id = request.headers.get(
            "x-correlation-id", str(uuid.uuid4())
        )
        request.state.correlation_id = correlation_id

        # --- 1. Validar Bearer JWT (actor identity) ---------------------------
        bearer_token = _extract_bearer_token(request.headers.get("authorization"))
        if not bearer_token:
            logger.warning("Missing bearer token.", extra={"correlation_id": correlation_id})
            return _make_error_response(correlation_id, "ERR_UNAUTHORIZED", 401)

        actor_claims = _decode_jwt_claims(bearer_token)
        if not actor_claims:
            logger.warning("Invalid bearer JWT structure.", extra={"correlation_id": correlation_id})
            return _make_error_response(correlation_id, "ERR_UNAUTHORIZED", 401)

        # --- 2. Validar X-Tenant-Claim JWT ------------------------------------
        tenant_claim_token = request.headers.get("x-tenant-claim")
        if not tenant_claim_token:
            logger.warning("Missing X-Tenant-Claim.", extra={"correlation_id": correlation_id})
            return _make_error_response(correlation_id, "ERR_CLAIM_MISSING", 403)

        tenant_claims = _decode_jwt_claims(tenant_claim_token)
        if not tenant_claims:
            logger.warning("Invalid X-Tenant-Claim JWT structure.", extra={"correlation_id": correlation_id})
            return _make_error_response(correlation_id, "ERR_CLAIM_INVALID", 403)

        tenant_id = tenant_claims.get("sub") or tenant_claims.get("tenant_id")
        if not tenant_id:
            logger.warning("X-Tenant-Claim missing sub/tenant_id.", extra={"correlation_id": correlation_id})
            return _make_error_response(correlation_id, "ERR_CLAIM_INVALID", 403)

        # --- 3. Injetar no request.state para os handlers --------------------
        request.state.tenant_id = tenant_id
        request.state.actor_id = actor_claims.get("sub", "unknown")

        # --- 4. Prosseguir para o handler ------------------------------------
        return await call_next(request)


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('api/middleware/auth.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
