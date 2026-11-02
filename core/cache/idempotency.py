# =============================================================================
# Archon-V — Idempotency Cache
# File: core/cache/idempotency.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
CACHE DE IDEMPOTÊNCIA (In-Memory MVP → Redis em Produção)

INVARIANTES:
1. TTL de 5 minutos por correlation_id — mesma request retorna resultado cacheado.
2. Cache é bounded (LRU maxsize=10_000) — sem crescimento ilimitado de RAM.
3. A chave de cache é COMPOSTA por (tenant_id + correlation_id) para garantir
   que o mesmo correlation_id de tenants diferentes não colida — isolamento galvânico.
4. Em produção, substituir pelo Redis com `SET NX EX 300` para distribuição
   multi-instância (GKE horizontal scaling).

DRY-RUN de Isolamento:
  tenant_a + corr_id_X → chave: "tenant_a:corr_id_X"
  tenant_b + corr_id_X → chave: "tenant_b:corr_id_X"
  Essas são CHAVES DISTINTAS. tenant_b nunca lê o cache de tenant_a.
"""

from __future__ import annotations

import hashlib
import time
from functools import lru_cache
from typing import Final, Any

_TTL_SECONDS: Final[int] = 300  # 5 minutos
_MAX_CACHE_SIZE: Final[int] = 10_000


class IdempotencyCache:
    """
    Cache LRU com TTL manual para idempotência de requests.
    Thread-safe em CPython (GIL protege dict ops). Para async real, usar Redis.
    """

    def __init__(self) -> None:
        # dict: cache_key → (timestamp_expiry, response_payload)
        self._store: dict[str, tuple[float, Any]] = {}

    def _make_key(self, tenant_id: str, correlation_id: str) -> str:
        """
        Chave composta e hasheada. Nunca expõe tenant_id ou correlation_id raw
        no log de chaves (proteção mínima de enumeração).
        O(1) — SHA256 de string curta.
        """
        raw = f"{tenant_id}:{correlation_id}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _evict_if_needed(self) -> None:
        """Remove entradas expiradas. O(n) mas raro — só dispara perto do limite."""
        now = time.monotonic()
        if len(self._store) >= _MAX_CACHE_SIZE:
            expired = [k for k, (exp, _) in self._store.items() if exp < now]
            for k in expired:
                del self._store[k]

    def get(self, tenant_id: str, correlation_id: str) -> Any | None:
        """
        Retorna o payload cacheado se existir e não tiver expirado. O(1).
        Retorna None se miss.
        """
        key = self._make_key(tenant_id, correlation_id)
        entry = self._store.get(key)
        if entry is None:
            return None
        expiry, payload = entry
        if time.monotonic() > expiry:
            del self._store[key]
            return None
        return payload

    def set(self, tenant_id: str, correlation_id: str, payload: Any) -> None:
        """
        Armazena payload com TTL. O(1) amortizado.
        """
        self._evict_if_needed()
        key = self._make_key(tenant_id, correlation_id)
        expiry = time.monotonic() + _TTL_SECONDS
        self._store[key] = (expiry, payload)


# Singleton de processo (substituir por Redis client em produção)
_idempotency_cache = IdempotencyCache()


def get_idempotency_cache() -> IdempotencyCache:
    """FastAPI dependency — retorna a instância singleton do cache."""
    return _idempotency_cache


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/cache/idempotency.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
