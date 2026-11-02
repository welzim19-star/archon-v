# =============================================================================
# Archon-V — Pytest Fixtures & Shared Test Utilities
# File: tests/conftest.py
# =============================================================================
"""
Fixtures compartilhadas entre testes unitários e de integração.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

import pytest

from api.v1.gate.schemas import (
    DeveloperMetadata,
    GitStagingContext,
    PreFlightCheckRequest,
    StagedFileDiff,
    DiffChangeType,
)


# --- GERAÇÃO DE CHAVES DE TESTE (RSA 2048) ---
_test_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
_test_private_pem = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

_test_public_pem = _test_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Injeta a chave pública na env var esperada pelo middleware
os.environ["ARCHON_IDP_PUBLIC_KEY"] = _test_public_pem


def _make_jwt_stub(payload: dict) -> str:
    """Gera um JWT com assinatura real (RS256) usando a chave de teste."""
    return jwt.encode(payload, _test_private_pem, algorithm="RS256")


@pytest.fixture
def tenant_id() -> str:
    return "acme-corp"


@pytest.fixture
def correlation_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def bearer_token(tenant_id) -> str:
    return _make_jwt_stub({"sub": f"dev@{tenant_id}.com", "iat": 9999999999})


@pytest.fixture
def tenant_claim_token(tenant_id) -> str:
    return _make_jwt_stub({"sub": tenant_id, "tenant_id": tenant_id, "iat": 9999999999})


def make_staged_file(
    file_path: str = "src/app.py",
    content: str = "x = 1",
    change_type: DiffChangeType = DiffChangeType.MODIFY,
) -> tuple[StagedFileDiff, str]:
    """
    Helper: cria um StagedFileDiff + retorna o conteúdo real para diff_contents.
    Garante que o SHA-256 é consistente.
    """
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    diff = StagedFileDiff(
        file_path=file_path,
        change_type=change_type,
        diff_content_sha256=sha,
        line_additions=5,
        line_deletions=2,
        mime_type="text/x-python",
    )
    return diff, content


@pytest.fixture
def clean_request(tenant_id, correlation_id) -> tuple[PreFlightCheckRequest, dict]:
    """Request com código limpo — deve retornar ALLOW."""
    diff, content = make_staged_file("src/utils.py", "def hello():\n    return 'world'\n")
    request = PreFlightCheckRequest(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        git_context=GitStagingContext(
            repository_id="github.com/acme/backend",
            branch_ref="refs/heads/feature/SEC-001",
            base_commit_sha="a" * 64,
            staged_files=[diff],
            staging_timestamp_utc=datetime.now(timezone.utc),
        ),
        developer=DeveloperMetadata(
            actor_id="dev@acme.com",
            workstation_fingerprint="b" * 64,
            agent_type="ide-plugin-vscode",
            agent_version="1.0.0",
        ),
        policy_set_version="1.0.0",
    )
    return request, {"src/utils.py": content}
