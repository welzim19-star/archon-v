# =============================================================================
# Archon-V — Immutable SHA-256 Audit Trail
# File: core/audit/trail.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
CADEIA DE AUDITORIA IMUTÁVEL — LGPD Art. 37 + TRÍADE CIA (Integridade)

LGPD Art. 37: "O controlador e o operador devem manter registro das operações
de tratamento de dados pessoais que realizarem." (REAT — Registro de Atividades
de Tratamento)

GARANTIAS DE INTEGRIDADE (CIA — Integrity):
  1. Cada entrada contém o hash SHA-256 da entrada anterior (cadeia encadeada).
     Qualquer adulteração em uma entrada invalida TODOS os hashes subsequentes.
     Isso é detectável em O(n) pelo verificador — auditoria matemática, não de confiança.

  2. Nenhuma entrada pode ser deletada individualmente — só toda a cadeia do tenant.
     (Direito ao esquecimento LGPD Art. 18 VI: aplica-se aos DADOS, não aos logs
     de auditoria de segurança, conforme LGPD Art. 16 I — tratamento para exercício
     de direitos em processo judicial, administrativo ou arbitral.)

  3. O `actor_id` é hasheado antes de entrar no log (pseudonimização, LGPD Art. 12).

  4. Campos como diff_content e PII NUNCA entram no audit trail — apenas
     correlation_id e action type.

ATORES REGISTRADOS:
  - TENANT_PROVISIONED       → novo tenant criado
  - TENANT_SUSPENDED         → tenant suspenso por violação/inadimplência  
  - TENANT_ERASED            → dados pessoais do tenant apagados (LGPD Art. 18 VI)
  - POLICY_RULESET_CREATED   → nova regra de política criada
  - POLICY_RULESET_DEPRECATED→ regra depreciada (nunca deletada — imutabilidade)
  - GATE_CHECK_PERFORMED     → interceptação executada (correlation_id only)
  - GATE_CHECK_BLOCKED       → commit bloqueado
  - KMS_KEY_ENROLLED         → BYOK key registrada
  - ADMIN_ACCESS             → acesso ao painel administrativo
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Final, Iterator

logger = logging.getLogger("archon_v.audit_trail")

_GENESIS_HASH: Final[str] = "0" * 64  # Hash sentinela para a primeira entrada


# ---------------------------------------------------------------------------
# ENUMERAÇÕES DE AÇÃO
# ---------------------------------------------------------------------------

class AuditAction(str, Enum):
    TENANT_PROVISIONED        = "TENANT_PROVISIONED"
    TENANT_SUSPENDED          = "TENANT_SUSPENDED"
    TENANT_ERASED             = "TENANT_ERASED"
    POLICY_RULESET_CREATED    = "POLICY_RULESET_CREATED"
    POLICY_RULESET_DEPRECATED = "POLICY_RULESET_DEPRECATED"
    GATE_CHECK_PERFORMED      = "GATE_CHECK_PERFORMED"
    GATE_CHECK_BLOCKED        = "GATE_CHECK_BLOCKED"
    KMS_KEY_ENROLLED          = "KMS_KEY_ENROLLED"
    ADMIN_ACCESS              = "ADMIN_ACCESS"


# ---------------------------------------------------------------------------
# ENTRADA DE AUDITORIA (Imutável após criação)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AuditEntry:
    """
    Entrada imutável na cadeia de auditoria.
    Nenhum campo pode ser modificado após criação (frozen=True).
    
    LGPD Art. 12: actor_id é pseudonimizado (SHA-256 antes de armazenar).
    LGPD Art. 37: todos os campos de ação e timestamp são preservados.
    """
    entry_id: str           # UUIDv4 único desta entrada
    tenant_id: str          # Tenant ao qual pertence
    action: AuditAction     # O que aconteceu
    actor_id_hash: str      # SHA-256 do actor_id (pseudonimização)
    correlation_id: str     # Linking com a request original
    timestamp_utc: str      # ISO 8601 UTC
    previous_hash: str      # Hash da entrada anterior (GENESIS se primeira)
    entry_hash: str         # SHA-256 desta entrada (garante integridade)
    metadata: str           # JSON string de metadados não-PII (ex: plan, rule_id)

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        action: AuditAction,
        actor_id: str,
        correlation_id: str,
        previous_hash: str,
        metadata: dict | None = None,
    ) -> "AuditEntry":
        """
        Factory method — única forma de criar uma AuditEntry.
        Pseudonimiza actor_id automaticamente.
        Computa entry_hash encadeando previous_hash.
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # LGPD Art. 12: pseudonimização do actor_id
        actor_id_hash = hashlib.sha256(actor_id.encode("utf-8")).hexdigest()

        metadata_str = json.dumps(metadata or {}, sort_keys=True, ensure_ascii=False)

        # Cadeia SHA-256: qualquer adulteração rompe a cadeia
        chain_input = (
            f"{previous_hash}|{entry_id}|{tenant_id}|{action.value}|"
            f"{actor_id_hash}|{timestamp}|{metadata_str}"
        )
        entry_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

        return cls(
            entry_id=entry_id,
            tenant_id=tenant_id,
            action=action,
            actor_id_hash=actor_id_hash,
            correlation_id=correlation_id,
            timestamp_utc=timestamp,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            metadata=metadata_str,
        )

    def to_dict(self) -> dict:
        """Serialização segura para resposta de API (sem PII)."""
        return {
            "entry_id": self.entry_id,
            "tenant_id": self.tenant_id,
            "action": self.action.value,
            "actor_id_hash": self.actor_id_hash,
            "correlation_id": self.correlation_id,
            "timestamp_utc": self.timestamp_utc,
            "entry_hash": self.entry_hash,
            # previous_hash e metadata omitidos da resposta pública
            # (internal chain verification only)
        }


# ---------------------------------------------------------------------------
# AUDIT TRAIL POR TENANT
# ---------------------------------------------------------------------------

class TenantAuditChain:
    """
    Cadeia de auditoria encadeada para um único tenant.
    Isolada por design — uma cadeia por tenant, nunca compartilhada.
    """

    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
        self._entries: list[AuditEntry] = []

    @property
    def head_hash(self) -> str:
        """Hash da entrada mais recente (ou GENESIS se vazia)."""
        return self._entries[-1].entry_hash if self._entries else _GENESIS_HASH

    def append(
        self,
        *,
        action: AuditAction,
        actor_id: str,
        correlation_id: str,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """
        Adiciona uma entrada à cadeia. O(1) amortizado.
        Encadeia automaticamente com o head_hash atual.
        """
        entry = AuditEntry.create(
            tenant_id=self._tenant_id,
            action=action,
            actor_id=actor_id,
            correlation_id=correlation_id,
            previous_hash=self.head_hash,
            metadata=metadata,
        )
        self._entries.append(entry)
        logger.info(
            "Audit entry recorded.",
            extra={
                "tenant_id": self._tenant_id,
                "action": action.value,
                "correlation_id": correlation_id,
                "entry_id": entry.entry_id,
            },
        )
        return entry

    def verify_integrity(self) -> bool:
        """
        Verifica a integridade de toda a cadeia. O(n).
        Recomputa cada entry_hash e verifica encadeamento.
        Retorna True se íntegra, False se adulterada.
        LGPD: evidência matemática de integridade para auditores.
        """
        prev_hash = _GENESIS_HASH
        for entry in self._entries:
            chain_input = (
                f"{prev_hash}|{entry.entry_id}|{entry.tenant_id}|{entry.action.value}|"
                f"{entry.actor_id_hash}|{entry.timestamp_utc}|{entry.metadata}"
            )
            expected_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
            if expected_hash != entry.entry_hash:
                logger.error(
                    "AUDIT CHAIN INTEGRITY FAILURE — possible tampering detected.",
                    extra={"tenant_id": self._tenant_id, "entry_id": entry.entry_id},
                )
                return False
            prev_hash = entry.entry_hash
        return True

    def get_entries(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """
        Retorna entradas paginadas (mais recentes primeiro). O(k) onde k=limit.
        """
        sliced = self._entries[-(offset + limit): len(self._entries) - offset]
        return [e.to_dict() for e in reversed(sliced)]

    def purge_for_erasure(self) -> int:
        """
        LGPD Art. 18 VI — Direito ao Esquecimento.
        Remove DADOS PESSOAIS das entradas (actor_id_hash → ERASED, metadata → {}).
        NÃO remove as entradas em si — o registro da AÇÃO permanece para compliance.
        Retorna o número de entradas anonimizadas.
        """
        count = 0
        anonymized: list[AuditEntry] = []
        for entry in self._entries:
            if entry.action == AuditAction.TENANT_ERASED:
                anonymized.append(entry)
                continue
            # Cria versão anonimizada (novo objeto imutável)
            anon = AuditEntry(
                entry_id=entry.entry_id,
                tenant_id="[ERASED]",
                action=entry.action,
                actor_id_hash="[ERASED]",
                correlation_id=entry.correlation_id,
                timestamp_utc=entry.timestamp_utc,
                previous_hash=entry.previous_hash,
                entry_hash=entry.entry_hash,  # Hash original preservado para auditoria
                metadata="{}",
            )
            anonymized.append(anon)
            count += 1
        self._entries = anonymized
        return count


# ---------------------------------------------------------------------------
# GERENCIADOR GLOBAL DE CADEIAS
# ---------------------------------------------------------------------------

class AuditTrailManager:
    """
    Gerencia cadeias de auditoria por tenant.
    Singleton de processo — em produção: persistir em Cloud Logging locked bucket.
    Isolamento galvânico: dict keyed por tenant_id, nunca shared.
    """

    def __init__(self) -> None:
        self._chains: dict[str, TenantAuditChain] = {}

    def _get_or_create_chain(self, tenant_id: str) -> TenantAuditChain:
        """O(1) — dict lookup + criação se necessário."""
        if tenant_id not in self._chains:
            self._chains[tenant_id] = TenantAuditChain(tenant_id)
        return self._chains[tenant_id]

    def record(
        self,
        *,
        tenant_id: str,
        action: AuditAction,
        actor_id: str,
        correlation_id: str,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Registra uma ação na cadeia do tenant."""
        chain = self._get_or_create_chain(tenant_id)
        return chain.append(
            action=action,
            actor_id=actor_id,
            correlation_id=correlation_id,
            metadata=metadata,
        )

    def get_entries(self, tenant_id: str, limit: int = 100, offset: int = 0) -> list[dict]:
        chain = self._chains.get(tenant_id)
        return chain.get_entries(limit=limit, offset=offset) if chain else []

    def verify_tenant_chain(self, tenant_id: str) -> bool:
        chain = self._chains.get(tenant_id)
        return chain.verify_integrity() if chain else True

    def erase_tenant_data(self, tenant_id: str) -> int:
        """LGPD Art. 18 VI — anonimiza dados pessoais da cadeia."""
        chain = self._chains.get(tenant_id)
        return chain.purge_for_erasure() if chain else 0


# Singleton
_audit_manager = AuditTrailManager()


def get_audit_manager() -> AuditTrailManager:
    return _audit_manager


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION
# python -c "import ast; ast.parse(open('core/audit/trail.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
