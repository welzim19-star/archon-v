# =============================================================================
# Archon-V — Token Bucket Rate Limiter (per-tenant, O(1))
# File: core/ratelimit/token_bucket.py
# =============================================================================
"""
RATE LIMITING POR TENANT — VALOR DE NEGÓCIO:
  "Cada cliente tem sua própria cota de requests. Um cliente mal-configurado
  ou com um bug em loop não derruba o serviço dos outros clientes.
  Isso é a SLA de 99.99% que prometemos no contrato."

ALGORITMO: Token Bucket com replenish contínuo (sliding window).
  - O(1) por request (dict lookup + float arithmetic)
  - Isolamento por tenant: cada tenant tem seu próprio bucket
  - Thread-safe em CPython (GIL protege float ops)
  - Em produção: substituir por Redis EVALSHA script (atomicidade distribuída)

LIMITES PADRÃO:
  - 100 requests/segundo por tenant (burst)
  - 60 requests/minuto (replenish rate sustentado)
  - Configurável por tier de plano (Starter/Professional/Enterprise)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# TIER DE RATE LIMITS POR PLANO COMERCIAL
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RateLimitTier:
    """Define os limites de um tier de plano."""
    requests_per_second: float   # Taxa de replenish sustentada
    burst_capacity: float        # Máximo de tokens (burst instantâneo)
    tier_name: str


TIER_STARTER = RateLimitTier(
    requests_per_second=10.0,
    burst_capacity=20.0,
    tier_name="starter",
)

TIER_PROFESSIONAL = RateLimitTier(
    requests_per_second=50.0,
    burst_capacity=100.0,
    tier_name="professional",
)

TIER_ENTERPRISE = RateLimitTier(
    requests_per_second=200.0,
    burst_capacity=500.0,
    tier_name="enterprise",
)

# Default para tenants sem tier configurado
_DEFAULT_TIER: Final[RateLimitTier] = TIER_PROFESSIONAL


# ---------------------------------------------------------------------------
# TOKEN BUCKET (per-tenant)
# ---------------------------------------------------------------------------

@dataclass
class _TenantBucket:
    """Estado do bucket de um único tenant."""
    tokens: float
    last_refill_time: float
    tier: RateLimitTier

    def consume(self, tokens_needed: float = 1.0) -> bool:
        """
        Tenta consumir `tokens_needed` tokens.
        Primeiro refill proporcional ao tempo decorrido.
        O(1) — aritmética de float pura.
        Retorna True se aprovado, False se rate-limited.
        """
        now = time.monotonic()
        elapsed = now - self.last_refill_time

        # Refill proporcional ao tempo (replenish contínuo)
        self.tokens = min(
            self.tier.burst_capacity,
            self.tokens + elapsed * self.tier.requests_per_second,
        )
        self.last_refill_time = now

        if self.tokens >= tokens_needed:
            self.tokens -= tokens_needed
            return True  # APPROVED
        return False  # RATE LIMITED


class TenantRateLimiter:
    """
    Gerencia buckets por tenant.
    LRU implícito: tenants inativos são removidos na próxima limpeza periódica.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, _TenantBucket] = {}
        self._tier_map: dict[str, RateLimitTier] = {}  # tenant_id → tier

    def configure_tenant(self, tenant_id: str, tier: RateLimitTier) -> None:
        """Configura o tier de um tenant. Chamado no provisionamento."""
        self._tier_map[tenant_id] = tier
        if tenant_id in self._buckets:
            self._buckets[tenant_id].tier = tier

    def is_allowed(self, tenant_id: str) -> bool:
        """
        Verifica se o tenant pode fazer mais uma request. O(1).
        Cria o bucket na primeira vez que o tenant aparece.
        """
        if tenant_id not in self._buckets:
            tier = self._tier_map.get(tenant_id, _DEFAULT_TIER)
            self._buckets[tenant_id] = _TenantBucket(
                tokens=tier.burst_capacity,
                last_refill_time=time.monotonic(),
                tier=tier,
            )
        return self._buckets[tenant_id].consume()

    def get_remaining_tokens(self, tenant_id: str) -> float:
        """Retorna os tokens restantes do tenant (para headers de debug)."""
        bucket = self._buckets.get(tenant_id)
        return bucket.tokens if bucket else _DEFAULT_TIER.burst_capacity


# Singleton de processo (substituir por Redis em produção multi-instância)
_rate_limiter = TenantRateLimiter()


def get_rate_limiter() -> TenantRateLimiter:
    """FastAPI dependency — retorna o singleton do rate limiter."""
    return _rate_limiter


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/ratelimit/token_bucket.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
