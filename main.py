# =============================================================================
# Archon-V — FastAPI Application Bootstrap
# File: main.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
PONTO DE ENTRADA DA APLICAÇÃO

Responsabilidades:
  1. Inicializar dependências singleton no lifespan (startup/shutdown seguro).
  2. Registrar middlewares na ordem correta (auth antes de tudo).
  3. Registrar routers.
  4. Expor endpoints de health/readiness para GKE probes.
  5. Garantir que nenhuma exception vaze stack trace para o cliente.

ORDEM DOS MIDDLEWARES (Starlette aplica de baixo para cima no registro):
  Requisição entra:  TrustedHost → CORS → Auth → Handler
  Resposta sai:      Handler → Auth → CORS → TrustedHost
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from api.middleware.auth import TenantAuthMiddleware
from api.v1.gate.router import router as gate_router
from core.tenant.resolver import TenantResolver

# ---------------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("archon_v.main")


# ---------------------------------------------------------------------------
# LIFESPAN (Startup / Shutdown seguro — sem recursos órfãos)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Gerencia o ciclo de vida completo da aplicação.
    Inicializa singletons pesados no startup; libera no shutdown.
    """
    logger.info("Archon-V starting up...")

    # --- Inicializar TenantResolver (singleton por processo) -----------------
    app.state.tenant_resolver = TenantResolver(
        gcp_project_id=os.environ.get("GCP_PROJECT_ID", "archon-v-dev"),
        kms_location=os.environ.get("GCP_KMS_LOCATION", "global"),
        db_host=os.environ.get("DB_HOST", "127.0.0.1"),
        db_port=int(os.environ.get("DB_PORT", "5432")),
        db_name_prefix=os.environ.get("DB_NAME_PREFIX", "archon_tenant"),
    )

    logger.info("TenantResolver initialized.")
    logger.info("Archon-V ready.")

    yield  # ← A aplicação roda aqui

    # --- Shutdown: liberar recursos ------------------------------------------
    logger.info("Archon-V shutting down gracefully...")
    # Em produção: fechar conexões de DB, flush de traces, etc.
    logger.info("Shutdown complete.")


# ---------------------------------------------------------------------------
# APLICAÇÃO FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Archon-V — Bastion Pre-Flight Security Gate",
    description=(
        "Enterprise SaaS DevSecOps proxy gate para enforcement pré-commit. "
        "Intercepta fluxos de IDEs e AI Agents para prevenção de PII leakage, "
        "secret bleeding e contract drift antes da persistência no Git."
    ),
    version="1.0.0",
    docs_url="/docs",          # Desabilitar em produção (docs_url=None)
    redoc_url="/redoc",        # Desabilitar em produção (redoc_url=None)
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# MIDDLEWARES (registrados do ÚLTIMO para o PRIMEIRO na cadeia de execução)
# ---------------------------------------------------------------------------

# 3. Auth (mais interno — executa logo antes do handler)
app.add_middleware(TenantAuthMiddleware)

# 2. CORS (configurar para o domínio do plugin apenas)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "").split(",") or ["*"],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "X-Tenant-Claim", "X-Correlation-Id", "X-Archon-HMAC", "Content-Type"],
)

# 1. Trusted Host (mais externo — primeiro a executar)
_allowed_hosts = os.environ.get("ALLOWED_HOSTS", "*").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)


# ---------------------------------------------------------------------------
# HANDLER GLOBAL DE EXCEÇÕES (garante zero stack trace para o cliente)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Captura QUALQUER exceção não tratada.
    Retorna apenas um Correlation ID — zero arquitetura exposta.
    """
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    logger.error(
        "Unhandled exception caught.",
        exc_info=True,
        extra={"correlation_id": correlation_id},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error_code": "ERR_INTERNAL",
            "correlation_id": correlation_id,
        },
    )


# ---------------------------------------------------------------------------
# ROUTERS
# ---------------------------------------------------------------------------

app.include_router(gate_router)


# ---------------------------------------------------------------------------
# HEALTH / READINESS PROBES (GKE Autopilot)
# ---------------------------------------------------------------------------

@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    """Liveness probe — responde 200 se o processo está vivo."""
    return {"status": "ok"}


@app.get("/ready", include_in_schema=False)
async def readiness(request: Request) -> dict[str, Any]:
    """
    Readiness probe — verifica se as dependências estão inicializadas.
    Retorna 503 se o TenantResolver não estiver pronto.
    """
    if not hasattr(request.app.state, "tenant_resolver"):
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# ENTRYPOINT (desenvolvimento local)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        reload=os.environ.get("ENV", "dev") == "dev",
        log_level="info",
    )

# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('main.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
