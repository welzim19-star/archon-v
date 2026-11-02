# =============================================================================
# Archon-V — Prometheus Metrics
# File: core/observability/metrics.py
# =============================================================================
"""
MÉTRICAS DE NEGÓCIO E OPERACIONAIS — VALOR DE NEGÓCIO:
  "Aqui está o nosso dashboard em tempo real. Você pode ver que o p99 de latência
  está em 87ms. O SLA contratual é 200ms. Estamos 57% abaixo do limite."

  Isso é o que fecha deals enterprise. Dados, não palavras.

MÉTRICAS EXPOSTAS em /metrics (formato Prometheus/OpenMetrics):
  archon_gate_requests_total        → Requests por tenant/verdict
  archon_gate_latency_seconds       → Histograma de latência (p50/p95/p99)
  archon_violations_total           → Violações por rule_id/severity
  archon_cache_operations_total     → Hit/miss de idempotência
  archon_kms_resolution_total       → Sucessos/falhas de resolução de tenant
  archon_active_tenants             → Gauge de tenants com requests nos últimos 5min
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False


# ---------------------------------------------------------------------------
# REGISTRY ISOLADO (evita conflito com métricas default do prometheus_client)
# ---------------------------------------------------------------------------

if _PROMETHEUS_AVAILABLE:
    REGISTRY = CollectorRegistry(auto_describe=True)

    # ── Requests totais por tenant e veredito ─────────────────────────────
    GATE_REQUESTS_TOTAL = Counter(
        "archon_gate_requests_total",
        "Total de requests ao pre-flight gate",
        ["tenant_id", "verdict"],   # Labels: acme-corp | ALLOW/BLOCK/WARN
        registry=REGISTRY,
    )

    # ── Latência do gate (SLO: p99 < 200ms) ──────────────────────────────
    GATE_LATENCY_SECONDS = Histogram(
        "archon_gate_latency_seconds",
        "Latência de processamento do pre-flight gate em segundos",
        ["tenant_id"],
        # Buckets calibrados para nosso SLO de p99 < 200ms
        buckets=[0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.5, 1.0],
        registry=REGISTRY,
    )

    # ── Violações detectadas por regra e severidade ───────────────────────
    VIOLATIONS_TOTAL = Counter(
        "archon_violations_total",
        "Total de violações de política detectadas",
        ["rule_id", "severity"],
        registry=REGISTRY,
    )

    # ── Cache de idempotência: hit/miss ────────────────────────────────────
    CACHE_OPERATIONS_TOTAL = Counter(
        "archon_cache_operations_total",
        "Operações de cache de idempotência",
        ["operation"],  # hit | miss | set
        registry=REGISTRY,
    )

    # ── Resolução KMS: sucesso/falha ──────────────────────────────────────
    KMS_RESOLUTION_TOTAL = Counter(
        "archon_kms_resolution_total",
        "Tentativas de resolução de tenant via KMS",
        ["result"],  # success | failure
        registry=REGISTRY,
    )

    # ── Gauge: tenants ativos (janela de 5min) ─────────────────────────────
    ACTIVE_TENANTS = Gauge(
        "archon_active_tenants",
        "Número de tenants com requests nos últimos 5 minutos",
        registry=REGISTRY,
    )

    def get_metrics_output() -> tuple[bytes, str]:
        """Retorna o output do Prometheus e o Content-Type header."""
        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST

else:
    # Stubs sem-ops quando prometheus_client não está instalado
    class _NoOpCounter:
        def labels(self, **_): return self
        def inc(self, *_): pass

    class _NoOpHistogram:
        def labels(self, **_): return self
        def observe(self, *_): pass

    class _NoOpGauge:
        def set(self, *_): pass
        def inc(self, *_): pass
        def dec(self, *_): pass

    GATE_REQUESTS_TOTAL = _NoOpCounter()
    GATE_LATENCY_SECONDS = _NoOpHistogram()
    VIOLATIONS_TOTAL = _NoOpCounter()
    CACHE_OPERATIONS_TOTAL = _NoOpCounter()
    KMS_RESOLUTION_TOTAL = _NoOpCounter()
    ACTIVE_TENANTS = _NoOpGauge()

    def get_metrics_output() -> tuple[bytes, str]:
        return b"# prometheus_client not installed\n", "text/plain"


# ---------------------------------------------------------------------------
# CONTEXT MANAGER — Mede latência automaticamente
# ---------------------------------------------------------------------------

@contextmanager
def measure_gate_latency(tenant_id: str) -> Generator[None, None, None]:
    """
    Context manager para medir latência do gate automaticamente.

    Uso:
        with measure_gate_latency(tenant_id):
            resultado = await processar_request()
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        if _PROMETHEUS_AVAILABLE:
            GATE_LATENCY_SECONDS.labels(tenant_id=tenant_id).observe(elapsed)


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/observability/metrics.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
