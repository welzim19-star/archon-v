# =============================================================================
# Archon-V — Interactive Demo & Pre-Flight Playground Router
# File: api/v1/demo/router.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
DEMO PLAYGROUND SANDBOX ENDPOINTS

Provides zero-barrier, zero-trust pre-flight security evaluation for interactive
browser testing and quick integration verification without requiring full GCP/KMS
credentials.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Final, Literal

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from api.v1.demo.html import PLAYGROUND_HTML
from core.interceptor.pii import PIIDetector
from core.interceptor.secrets import SecretScanner
from core.ratelimit.token_bucket import RateLimitTier, TenantRateLimiter

logger = logging.getLogger("archon_v.demo_router")

router = APIRouter(tags=["DevSecOps Playground"])

# Demo Rate Limiter — 8 burst tokens, 5 rps refill
_DEMO_TIER: Final[RateLimitTier] = RateLimitTier(
    requests_per_second=5.0,
    burst_capacity=8.0,
    tier_name="demo-playground",
)
_demo_limiter: Final[TenantRateLimiter] = TenantRateLimiter()

# Singletons for zero-allocation regex evaluation
_secret_scanner: Final[SecretScanner] = SecretScanner()
_pii_detector: Final[PIIDetector] = PIIDetector()


# ---------------------------------------------------------------------------
# SCHEMAS
# ---------------------------------------------------------------------------

class DemoScanRequest(BaseModel):
    """Payload for code / diff scanning in sandbox mode."""
    model_config = {"frozen": True}

    content: str = Field(
        ...,
        max_length=1_048_576,
        description="Source code or diff text to scan (max 1MB).",
    )
    filename: str = Field(
        default="snippet.py",
        max_length=255,
        description="Virtual file path for context evaluation.",
    )
    scanner_type: Literal["all", "secrets", "pii"] = Field(
        default="all",
        description="Scanning engine subset to execute.",
    )


class FindingItem(BaseModel):
    rule_id: str
    severity: str
    description: str
    remediation_hint: str


class DemoScanResponse(BaseModel):
    verdict: Literal["ALLOWED", "BLOCKED", "RATE_LIMITED"]
    findings: list[FindingItem]
    latency_ms: float
    content_sha256: str
    correlation_id: str
    audit_hash: str
    timestamp: str
    scanned_bytes: int
    filename: str


# ---------------------------------------------------------------------------
# PLAYGROUND UI ENDPOINTS
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def playground_root() -> HTMLResponse:
    """Serve the interactive DevSecOps Playground UI directly at root."""
    return HTMLResponse(content=PLAYGROUND_HTML, status_code=200)


@router.get("/api/v1/demo", response_class=HTMLResponse, include_in_schema=False)
async def playground_alias() -> HTMLResponse:
    """Serve the interactive DevSecOps Playground UI at /api/v1/demo."""
    return HTMLResponse(content=PLAYGROUND_HTML, status_code=200)


# ---------------------------------------------------------------------------
# SANDBOX SCANNING & HEALTH APIS
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/demo/scan",
    response_model=DemoScanResponse,
    responses={
        429: {
            "description": "Token bucket rate limit exceeded (burst protection active)",
        }
    },
)
async def demo_scan(payload: DemoScanRequest, request: Request) -> JSONResponse:
    """
    Execute zero-trust pre-flight gate evaluation against submitted code snippet.
    Includes token-bucket rate limiting, regex secret scanning, and PII detection.
    """
    # 1. Rate Limiting Check
    client_ip = request.client.host if request.client else "demo-client"
    _demo_limiter.configure_tenant(client_ip, _DEMO_TIER)
    allowed = _demo_limiter.is_allowed(client_ip)

    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "1"},
            content={
                "error_code": "ERR_RATE_LIMITED",
                "verdict": "RATE_LIMITED",
                "message": (
                    "Token bucket capacity depleted (burst protection active). "
                    "Rate limiter prevents noisy neighbor resource exhaustion."
                ),
                "retry_after_seconds": 1,
            },
        )

    # 2. Start high-resolution timer
    t0 = time.perf_counter()

    content_bytes = payload.content.encode("utf-8")
    content_sha = hashlib.sha256(content_bytes).hexdigest()
    correlation_id = str(uuid.uuid4())

    findings: list[FindingItem] = []

    # 3. Secrets scan
    if payload.scanner_type in ("all", "secrets"):
        for sec in _secret_scanner.scan(payload.content):
            findings.append(
                FindingItem(
                    rule_id=sec.rule_id,
                    severity="CRITICAL",
                    description=sec.description,
                    remediation_hint=(
                        "Rotate exposed secret immediately and migrate to an environment variable "
                        "or Secret Manager."
                    ),
                )
            )

    # 4. PII scan
    if payload.scanner_type in ("all", "pii"):
        for pii in _pii_detector.scan(payload.content):
            findings.append(
                FindingItem(
                    rule_id=pii.rule_id,
                    severity="CRITICAL",
                    description=pii.description,
                    remediation_hint=(
                        "Replace sensitive personally identifiable information (PII) with synthetic "
                        "test mocks or scrub from codebase."
                    ),
                )
            )

    # 5. Determine Verdict
    verdict: Literal["ALLOWED", "BLOCKED"] = "BLOCKED" if findings else "ALLOWED"

    # 6. Audit Trail Hash (simulating cryptographic chain link)
    audit_preimage = f"{correlation_id}:{content_sha}:{verdict}".encode("utf-8")
    audit_hash = hashlib.sha256(audit_preimage).hexdigest()

    latency_ms = round((time.perf_counter() - t0) * 1000, 3)

    response_data = DemoScanResponse(
        verdict=verdict,
        findings=findings,
        latency_ms=latency_ms,
        content_sha256=content_sha,
        correlation_id=correlation_id,
        audit_hash=audit_hash,
        timestamp=datetime.now(timezone.utc).isoformat(),
        scanned_bytes=len(content_bytes),
        filename=payload.filename,
    )

    return JSONResponse(status_code=200, content=response_data.model_dump())


@router.get("/api/v1/demo/health", tags=["DevSecOps Playground"])
async def demo_health() -> dict[str, object]:
    """Inspect status of demo playground and active rulesets."""
    return {
        "status": "online",
        "service": "Archon-V DevSecOps Playground",
        "version": "1.0.0",
        "rules_active": {
            "secrets_regex_count": 4,
            "pii_regex_count": 3,
        },
        "rate_limiter": {
            "algorithm": "token_bucket",
            "burst_capacity": _DEMO_TIER.burst_capacity,
            "refill_rate_rps": _DEMO_TIER.requests_per_second,
        },
        "max_payload_bytes": 1_048_576,
    }
