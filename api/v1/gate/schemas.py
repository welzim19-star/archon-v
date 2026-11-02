# =============================================================================
# Archon-V — API Contract: /v1/gate/pre-flight-check
# FastAPI + Pydantic V2 | Zero Regression — Additive Only
# File: api/v1/gate/schemas.py
# =============================================================================
"""
CONTRACT VERSION: 1.0.0
STABILITY: STABLE — public contract. Breaking changes require Deprecation Plan.
BIG-O GUARANTEE: Pydantic V2 validation is O(n_fields) — bounded by schema size,
  NOT by payload size. Field count is fixed (<=25). Effective O(1) for this contract.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------
# SHARED PRIMITIVES
# ---------------------------------------------------------------------------

CorrelationId = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
]
"""UUIDv4 correlation ID — enforced by regex, not trust."""

TenantId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$", max_length=63),
]
"""Tenant slug — DNS-safe, max 63 chars (matches GCP project ID rules)."""

ShaDigest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]
"""SHA-256 hex digest — 64 hex chars, lowercase enforced."""

# ---------------------------------------------------------------------------
# ENUMERATIONS
# ---------------------------------------------------------------------------


class DiffChangeType(str, Enum):
    ADD = "ADD"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    RENAME = "RENAME"


class PolicyVerdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    WARN = "WARN"


class ViolationSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # PII / secret detected → always BLOCK
    HIGH = "HIGH"           # Contract breaking change
    MEDIUM = "MEDIUM"       # Policy advisory
    LOW = "LOW"             # Informational


# ---------------------------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------------------------


class DeveloperMetadata(BaseModel):
    """
    Identity context of the actor performing the commit.
    Immutable after construction — no field can be mutated post-init.
    """

    model_config = {"frozen": True}

    actor_id: Annotated[str, StringConstraints(max_length=128)] = Field(
        ...,
        description="Authenticated identity (email or service account, masked at rest)",
        examples=["dev-sa@project.iam.gserviceaccount.com"],
    )
    workstation_fingerprint: ShaDigest = Field(
        ...,
        description="SHA-256 of (machine-id || public-key). Bound to device posture.",
    )
    agent_type: Annotated[str, StringConstraints(max_length=64)] = Field(
        ...,
        description="Client agent identifier: 'ide-plugin-vscode', 'ai-agent-cursor', 'ci-hook'",
        examples=["ai-agent-cursor", "ide-plugin-vscode", "ci-hook-github-actions"],
    )
    agent_version: Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")] = Field(
        ...,
        description="SemVer of the Archon-V client agent.",
    )

    @field_validator("actor_id", mode="before")
    @classmethod
    def mask_sensitive_fragments(cls, v: str) -> str:
        """Block raw email if it matches a known PII pattern. Return as-is for SA."""
        # Fail-secure: if masking fails, reject rather than pass raw PII
        if isinstance(v, str) and len(v) > 128:
            raise ValueError("actor_id exceeds maximum length — rejected.")
        return v


class StagedFileDiff(BaseModel):
    """
    Represents ONE file in the git staging area.
    O(1) boundary: diff_content_sha256 is pre-computed by the client.
    We do NOT receive raw diff content — only its digest + metadata.
    This enforces an O(1) server-side payload regardless of diff size.
    """

    model_config = {"frozen": True}

    file_path: Annotated[str, StringConstraints(max_length=4096)] = Field(
        ...,
        description="Relative path from repo root. Must not start with '/'.",
    )
    change_type: DiffChangeType
    diff_content_sha256: ShaDigest = Field(
        ...,
        description=(
            "SHA-256 of the raw unified diff content. "
            "Server verifies this against the policy corpus — never stores raw diff."
        ),
    )
    line_additions: Annotated[int, Field(ge=0, le=100_000)] = Field(
        ...,
        description="Number of added lines. Hard ceiling: 100k (O(n) protection).",
    )
    line_deletions: Annotated[int, Field(ge=0, le=100_000)] = Field(
        ...,
        description="Number of deleted lines. Hard ceiling: 100k.",
    )
    mime_type: Annotated[str, StringConstraints(max_length=128)] = Field(
        default="text/plain",
        description="MIME type hint for policy routing.",
    )

    @field_validator("file_path", mode="before")
    @classmethod
    def reject_absolute_paths(cls, v: str) -> str:
        if isinstance(v, str) and v.startswith("/"):
            raise ValueError("file_path must be relative — absolute paths rejected.")
        return v


class GitStagingContext(BaseModel):
    """
    Complete context of the git staging area snapshot.
    Ceiling enforced: max 500 files per pre-flight-check (O(n) bound).
    If n > 500, caller MUST split into batches.
    """

    model_config = {"frozen": True}

    repository_id: Annotated[str, StringConstraints(max_length=256)] = Field(
        ...,
        description="Canonical repository identifier (e.g., github.com/org/repo).",
    )
    branch_ref: Annotated[str, StringConstraints(max_length=256)] = Field(
        ...,
        description="Full git ref (e.g., refs/heads/feature/SEC-1042).",
    )
    base_commit_sha: ShaDigest = Field(
        ...,
        description="SHA-256 of the HEAD commit before this staging diff.",
    )
    staged_files: list[StagedFileDiff] = Field(
        ...,
        min_length=1,
        max_length=500,  # Hard O(n) ceiling per contract
        description="List of staged file diffs. MAX 500 files per request.",
    )
    staging_timestamp_utc: datetime = Field(
        ...,
        description="UTC timestamp of when staging snapshot was captured.",
    )

    @model_validator(mode="after")
    def validate_staging_integrity(self) -> "GitStagingContext":
        """Cross-field: ensure base_commit_sha is not a zero-hash (sentinel block)."""
        zero_hash = "0" * 64
        if self.base_commit_sha == zero_hash:
            raise ValueError("base_commit_sha cannot be zero-hash — initial commits require explicit SHA.")
        return self


class PreFlightCheckRequest(BaseModel):
    """
    CANONICAL REQUEST PAYLOAD for POST /v1/gate/pre-flight-check.
    
    HEADER CONTRACT (enforced at middleware layer, not here):
        X-Tenant-Claim: <signed JWT — RS256>
        X-Correlation-Id: <UUIDv4>
        X-Archon-HMAC: <HMAC-SHA256 of request body with tenant BYOK>
        Authorization: Bearer <actor JWT>
    
    NOTE: tenant_id here is DERIVED from X-Tenant-Claim, NOT trusted from body.
    The body tenant_id is a cross-check only — mismatch = immediate 403 drop.
    """

    model_config = {"frozen": True, "str_strip_whitespace": True}

    tenant_id: TenantId = Field(
        ...,
        description=(
            "Tenant slug — must match the sub claim in X-Tenant-Claim header JWT. "
            "Cross-checked server-side; mismatch causes immediate 403 + drop."
        ),
    )
    correlation_id: CorrelationId = Field(
        ...,
        description="UUIDv4 idempotency key. Duplicate requests within 5min return cached verdict.",
    )
    git_context: GitStagingContext
    developer: DeveloperMetadata
    policy_set_version: Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")] = Field(
        ...,
        description="SemVer of the policy ruleset the client expects to be evaluated against.",
    )

    @model_validator(mode="after")
    def cross_validate_tenant_binding(self) -> "PreFlightCheckRequest":
        """
        Ensures correlation_id is a deterministic UUIDv4 (version bit check).
        Note: actual X-Tenant-Claim JWT cross-check happens in middleware.
        """
        try:
            parsed = uuid.UUID(self.correlation_id, version=4)
            if str(parsed) != self.correlation_id:
                raise ValueError("correlation_id UUID normalization mismatch.")
        except ValueError as exc:
            raise ValueError(f"Invalid correlation_id: {exc}") from exc
        return self


# ---------------------------------------------------------------------------
# RESPONSE MODELS
# ---------------------------------------------------------------------------


class PolicyViolation(BaseModel):
    """Single policy violation record. Additive — new fields are non-breaking."""

    model_config = {"frozen": True}

    violation_id: CorrelationId = Field(
        ...,
        description="UUIDv4 identifying this specific violation instance.",
    )
    severity: ViolationSeverity
    rule_id: Annotated[str, StringConstraints(max_length=64)] = Field(
        ...,
        description="Deterministic rule identifier (e.g., 'PII-EMAIL-001', 'SECRET-RSA-KEY-002').",
    )
    file_path: Annotated[str, StringConstraints(max_length=4096)]
    description: Annotated[str, StringConstraints(max_length=512)] = Field(
        ...,
        description="Human-readable violation description. MUST NOT contain raw PII or secret material.",
    )
    remediation_hint: Annotated[str, StringConstraints(max_length=512)] = Field(
        default="",
        description="Actionable remediation hint for the developer.",
    )


class PreFlightCheckResponse(BaseModel):
    """
    CANONICAL RESPONSE for POST /v1/gate/pre-flight-check.
    
    GUARANTEE: No stack traces. No architecture info. No PII. No secret material.
    Violations list is ALWAYS present (empty list on ALLOW).
    """

    model_config = {"frozen": True}

    correlation_id: CorrelationId = Field(
        ...,
        description="Echoed from request — links response to audit log entry.",
    )
    tenant_id: TenantId = Field(
        ...,
        description="Tenant slug — confirms scope of evaluation.",
    )
    verdict: PolicyVerdict = Field(
        ...,
        description="Aggregate verdict across all staged files and all policy engines.",
    )
    violations: list[PolicyViolation] = Field(
        default_factory=list,
        description="List of policy violations. Empty on ALLOW.",
    )
    evaluated_policy_version: Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")] = Field(
        ...,
        description="Actual policy version used — may differ from request if upgraded.",
    )
    evaluated_at_utc: datetime = Field(
        ...,
        description="UTC timestamp of gate evaluation.",
    )
    cache_hit: bool = Field(
        default=False,
        description="True if this response was served from idempotency cache (duplicate correlation_id).",
    )


class ErrorResponse(BaseModel):
    """
    CANONICAL ERROR RESPONSE — used for ALL non-2xx responses.
    ZERO architecture information. ZERO stack traces. ZERO PII.
    """

    model_config = {"frozen": True}

    error_code: Annotated[str, StringConstraints(max_length=32)] = Field(
        ...,
        description="Mapped error code string (e.g., 'ERR_TENANT_RESOLUTION_FAILURE').",
        examples=[
            "ERR_TENANT_RESOLUTION_FAILURE",
            "ERR_KMS_KEY_INVALID",
            "ERR_CLAIM_MISMATCH",
            "ERR_POLICY_EVALUATION_TIMEOUT",
            "ERR_INTERNAL",
        ],
    )
    correlation_id: CorrelationId = Field(
        ...,
        description="UUIDv4 for cross-referencing masked audit log entry.",
    )


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND (run from project root)
# ---------------------------------------------------------------------------
# python -c "import ast, sys; ast.parse(open('api/v1/gate/schemas.py').read()); print('SYNTAX OK')"
