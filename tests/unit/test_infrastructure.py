# =============================================================================
# Archon-V — Unit Tests: Idempotency Cache + Rate Limiter
# File: tests/unit/test_infrastructure.py
# =============================================================================
import time
import pytest

from core.cache.idempotency import IdempotencyCache
from core.ratelimit.token_bucket import TenantRateLimiter, TIER_STARTER, TIER_ENTERPRISE


# ─── IDEMPOTENCY CACHE ────────────────────────────────────────────────────────

class TestIdempotencyCache:

    @pytest.fixture
    def cache(self) -> IdempotencyCache:
        return IdempotencyCache()

    def test_miss_returns_none(self, cache):
        result = cache.get("tenant-a", "corr-123")
        assert result is None

    def test_set_and_get_returns_payload(self, cache):
        payload = {"verdict": "ALLOW", "violations": []}
        cache.set("tenant-a", "corr-123", payload)
        result = cache.get("tenant-a", "corr-123")
        assert result == payload

    def test_tenant_isolation_in_cache(self, cache):
        """tenant-a e tenant-b com mesmo correlation_id NÃO colidem. Galvânico."""
        payload_a = {"verdict": "ALLOW"}
        payload_b = {"verdict": "BLOCK"}
        cache.set("tenant-a", "corr-shared", payload_a)
        cache.set("tenant-b", "corr-shared", payload_b)

        # Cada tenant vê apenas o seu próprio resultado
        assert cache.get("tenant-a", "corr-shared") == payload_a
        assert cache.get("tenant-b", "corr-shared") == payload_b

    def test_different_correlation_ids_are_independent(self, cache):
        cache.set("tenant-a", "corr-111", {"verdict": "ALLOW"})
        cache.set("tenant-a", "corr-222", {"verdict": "BLOCK"})

        assert cache.get("tenant-a", "corr-111")["verdict"] == "ALLOW"
        assert cache.get("tenant-a", "corr-222")["verdict"] == "BLOCK"

    def test_overwrite_same_key(self, cache):
        cache.set("tenant-a", "corr-x", {"verdict": "ALLOW"})
        cache.set("tenant-a", "corr-x", {"verdict": "BLOCK"})
        # O segundo set sobrescreve (comportamento correto para retry de idempotência)
        result = cache.get("tenant-a", "corr-x")
        assert result["verdict"] == "BLOCK"


# ─── RATE LIMITER ─────────────────────────────────────────────────────────────

class TestTenantRateLimiter:

    @pytest.fixture
    def limiter(self) -> TenantRateLimiter:
        return TenantRateLimiter()

    def test_new_tenant_is_allowed(self, limiter):
        """Primeiro request de qualquer tenant é sempre permitido."""
        assert limiter.is_allowed("new-tenant") is True

    def test_burst_capacity_respected(self, limiter):
        """Starter: burst de 20 requests simultâneos."""
        limiter.configure_tenant("burst-tenant", TIER_STARTER)
        # Primeiros 20 devem passar (burst capacity = 20)
        results = [limiter.is_allowed("burst-tenant") for _ in range(20)]
        assert all(results), "Burst capacity not respected — requests blocked too early"

    def test_exceeding_burst_is_rate_limited(self, limiter):
        """Após esgotar o burst, requests devem ser bloqueados."""
        limiter.configure_tenant("exhausted-tenant", TIER_STARTER)
        # Esgotar todos os tokens
        for _ in range(20):
            limiter.is_allowed("exhausted-tenant")
        # O próximo request deve ser bloqueado
        assert limiter.is_allowed("exhausted-tenant") is False

    def test_tenant_isolation_in_rate_limiter(self, limiter):
        """Rate limit de um tenant não afeta outro tenant."""
        limiter.configure_tenant("tenant-x", TIER_STARTER)
        # Esgotar tenant-x
        for _ in range(21):
            limiter.is_allowed("tenant-x")
        # tenant-y (fresh) ainda deve passar
        limiter.configure_tenant("tenant-y", TIER_STARTER)
        assert limiter.is_allowed("tenant-y") is True

    def test_enterprise_has_higher_burst(self, limiter):
        """Enterprise tier tem burst 500x maior que Starter."""
        limiter.configure_tenant("enterprise-client", TIER_ENTERPRISE)
        # 100 requests rápidos devem passar com tier Enterprise
        results = [limiter.is_allowed("enterprise-client") for _ in range(100)]
        assert all(results), "Enterprise tier should allow 100 burst requests"

    def test_get_remaining_tokens_decreases(self, limiter):
        """Tokens diminuem após cada request aprovado."""
        limiter.configure_tenant("tokens-tenant", TIER_ENTERPRISE)
        # Primeiro is_allowed inicializa o bucket — tokens = burst_capacity - 1
        limiter.is_allowed("tokens-tenant")
        after_first = limiter.get_remaining_tokens("tokens-tenant")
        limiter.is_allowed("tokens-tenant")
        after_second = limiter.get_remaining_tokens("tokens-tenant")
        # Cada chamada consome 1 token — after_second deve ser menor
        assert after_second < after_first
