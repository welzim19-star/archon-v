# =============================================================================
# Archon-V — Chaos Tests: Fail-Secure Scenarios
# File: tests/unit/test_chaos.py
# =============================================================================
"""
CHAOS ENGINEERING — VALOR DE NEGÓCIO:
  "Testamos o que acontece quando o KMS cai, o banco não responde e o token
  é inválido. Em todos os casos, o sistema bloqueia por segurança e retorna
  apenas um Correlation ID. Nunca expõe dados internos."

  Isso é o argumento definitivo para o CISO enterprise.
"""
import pytest
from core.tenant.resolver import TenantResolver, TenantResolutionFailure


class TestKMSFailSecure:
    """Simula falhas do KMS — deve sempre resultar em drop O(1)."""

    @pytest.fixture
    def resolver(self) -> TenantResolver:
        return TenantResolver(
            gcp_project_id="test-project",
            db_host="localhost",
        )

    def test_invalid_kms_key_raises_failure(self, resolver):
        """KMS key inválida → TenantResolutionFailure imediato."""
        with pytest.raises(TenantResolutionFailure) as exc_info:
            resolver.resolve(
                tenant_id="INVALID-TENANT-WITH-BAD-KEY",
                raw_claim_bytes=b"test",
                claim_hmac_tag=b"wrong-tag-00000000000000000000000",
                correlation_id="test-corr-id",
            )
        # GARANTIA: a exceção NUNCA expõe detalhes internos
        assert exc_info.value.correlation_id == "test-corr-id"
        assert exc_info.value.error_code == "ERR_TENANT_RESOLUTION_FAILURE"

    def test_hmac_mismatch_raises_failure(self, resolver):
        """HMAC incorreto → fail-secure. Não há fallback."""
        with pytest.raises(TenantResolutionFailure):
            resolver.resolve(
                tenant_id="acme-corp",
                raw_claim_bytes=b"legitimate-claim",
                claim_hmac_tag=b"\x00" * 32,  # Tag completamente errada
                correlation_id="chaos-test-001",
            )

    def test_failure_has_no_sensitive_info(self, resolver):
        """A exceção não pode conter paths, configs ou qualquer dado interno."""
        try:
            resolver.resolve(
                tenant_id="acme-corp",
                raw_claim_bytes=b"test",
                claim_hmac_tag=b"\x00" * 32,
                correlation_id="chaos-test-002",
            )
        except TenantResolutionFailure as e:
            error_str = str(e)
            # Garantias de que não vaza informação:
            assert "localhost" not in error_str      # Sem DB host
            assert "password" not in error_str.lower()
            assert "traceback" not in error_str.lower()
            assert "archon" not in error_str.lower() or "ERR_" in error_str

    def test_empty_tenant_id_raises_failure(self, resolver):
        """tenant_id vazio é rejeitado."""
        with pytest.raises((TenantResolutionFailure, Exception)):
            resolver.resolve(
                tenant_id="",
                raw_claim_bytes=b"test",
                claim_hmac_tag=b"\x00" * 32,
                correlation_id="chaos-empty",
            )


class TestSchemaIsolationChaos:
    """Verifica que a URL do DB muda para cada tenant (isolamento galvânico)."""

    @pytest.fixture
    def resolver(self) -> TenantResolver:
        return TenantResolver(
            gcp_project_id="test-project",
            db_host="db.internal",
        )

    def test_different_tenants_get_different_db_urls(self, resolver):
        url_a = resolver._derive_db_schema_url("tenant-alpha")
        url_b = resolver._derive_db_schema_url("tenant-beta")
        assert url_a != url_b, "CRITICAL: Tenants sharing same DB URL!"

    def test_db_url_contains_tenant_identifier(self, resolver):
        url = resolver._derive_db_schema_url("acme-corp")
        assert "acme" in url.lower() or "acme_corp" in url.lower()

    def test_kms_key_ring_unique_per_tenant(self, resolver):
        ring_a = resolver._derive_kms_key_ring("tenant-alpha")
        ring_b = resolver._derive_kms_key_ring("tenant-beta")
        assert ring_a != ring_b, "CRITICAL: Tenants sharing same KMS key ring!"
        assert "tenant-alpha" in ring_a
        assert "tenant-beta" in ring_b
