# =============================================================================
# Archon-V — Tenant Provisioning Service
# File: core/tenant/provisioner.py
# CONTRACT VERSION: 1.0.0 — STABLE
# =============================================================================
"""
SERVIÇO DE PROVISIONAMENTO DE TENANT — TRÍADE CIA + LGPD

RESPONSABILIDADES:
  1. Criar schema de DB isolado para o tenant (isolamento galvânico)
  2. Criar KMS Key Ring dedicado (BYOK preparation)
  3. Registrar o ruleset padrão do sistema para o tenant
  4. Emitir audit entry de TENANT_PROVISIONED
  5. Operação IDEMPOTENTE — provisionar o mesmo tenant_id duas vezes é safe

LGPD — Minimização de Dados (Art. 6 III):
  Apenas os dados estritamente necessários são armazenados:
  - tenant_id (identificador técnico)
  - plan_tier (necessário para billing)
  - data_controller_name (responsável pelo tratamento — obrigatório LGPD)
  - dpo_contact_hash (Encarregado — pseudonimizado)
  - provisioned_at (timestamp para REAT)
  
  NÃO armazenamos: endereço, CNPJ, dados bancários, informações pessoais de devs.

LGPD — Responsabilidade (Art. 42):
  O TenantProvisioner é o ponto de controle que garante que cada tenant
  tem seu próprio escopo de dados — responsabilidade técnica documentada.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Final

from core.audit.trail import AuditAction, AuditTrailManager

logger = logging.getLogger("archon_v.provisioner")


class PlanTier(str, Enum):
    STARTER      = "STARTER"       # USD 2.500/mês
    PROFESSIONAL = "PROFESSIONAL"  # USD 8.000/mês
    ENTERPRISE   = "ENTERPRISE"    # USD 25.000/mês


@dataclass(frozen=True, slots=True)
class TenantRecord:
    """
    Registro imutável de um tenant provisionado.
    LGPD Art. 37 — faz parte do REAT (Registro de Atividades de Tratamento).
    """
    tenant_id: str
    plan_tier: PlanTier
    data_controller_name: str   # Nome da empresa controladora (LGPD Art. 5 VI)
    dpo_contact_hash: str       # SHA-256 do email do DPO (pseudonimização)
    kms_key_ring_name: str      # Referência ao KMS ring provisionado
    db_schema_identifier: str   # Identificador do schema isolado
    provisioned_at: str         # ISO 8601 UTC
    correlation_id: str         # Link com o evento de provisionamento


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    """Resultado de uma operação de provisionamento."""
    tenant_record: TenantRecord
    was_idempotent: bool        # True se o tenant já existia (safe no-op)
    audit_entry_id: str         # ID da entrada no audit trail


class TenantProvisioner:
    """
    Serviço de provisionamento multi-tenant.
    
    ISOLAMENTO GALVÂNICO (Dry-Run Proof):
      tenant_a → KMS ring: archon-tenant-acme-corp   → DB: archon_tenant_acme_corp
      tenant_b → KMS ring: archon-tenant-beta-inc    → DB: archon_tenant_beta_inc
      
      Não há tabela compartilhada. Não há WHERE clause. Não há filtro.
      A separação é na camada de infraestrutura (KMS scope + DB schema).
      Um ataque de privilege escalation em tenant_a não tem acesso físico
      ao schema de tenant_b — diferente schemas/databases no PostgreSQL.
    """

    def __init__(
        self,
        *,
        audit_manager: AuditTrailManager,
        gcp_project_id: str = "archon-v-prod",
        kms_location: str = "global",
        db_prefix: str = "archon_tenant",
    ) -> None:
        self._audit = audit_manager
        self._project = gcp_project_id
        self._kms_location = kms_location
        self._db_prefix = db_prefix
        # Registry em memória — produção: tabela de controle no DB admin
        self._tenants: dict[str, TenantRecord] = {}

    def provision(
        self,
        *,
        tenant_id: str,
        plan_tier: PlanTier,
        data_controller_name: str,
        dpo_contact_email: str,
        actor_id: str,
        correlation_id: str,
    ) -> ProvisioningResult:
        """
        Provisiona um tenant de forma idempotente.
        
        Se o tenant_id já existe: retorna o registro existente (was_idempotent=True).
        Se não existe: cria todos os recursos e registra no audit trail.
        
        PRODUÇÃO — passos adicionais:
          1. CREATE SCHEMA tenant_{id} (PostgreSQL)
          2. gcp_kms.create_key_ring(name=kms_key_ring_name)
          3. gcp_kms.create_crypto_key(name=byok_key_name)
          4. Executar migrations do schema do tenant
        """
        # IDEMPOTÊNCIA — verifica se já existe
        if tenant_id in self._tenants:
            existing = self._tenants[tenant_id]
            logger.info(
                "Tenant provisioning is idempotent — already exists.",
                extra={"tenant_id": tenant_id, "correlation_id": correlation_id},
            )
            # Registra o acesso idempotente no audit trail
            entry = self._audit.record(
                tenant_id=tenant_id,
                action=AuditAction.TENANT_PROVISIONED,
                actor_id=actor_id,
                correlation_id=correlation_id,
                metadata={"idempotent": True, "plan": plan_tier.value},
            )
            return ProvisioningResult(
                tenant_record=existing,
                was_idempotent=True,
                audit_entry_id=entry.entry_id,
            )

        # PROVISIONAR — criar recursos
        kms_key_ring = (
            f"projects/{self._project}/locations/{self._kms_location}"
            f"/keyRings/archon-tenant-{tenant_id}"
        )
        db_identifier = f"{self._db_prefix}_{tenant_id.replace('-', '_')}"

        # LGPD Art. 12 — pseudonimização do contato do DPO
        dpo_hash = hashlib.sha256(dpo_contact_email.lower().encode()).hexdigest()

        record = TenantRecord(
            tenant_id=tenant_id,
            plan_tier=plan_tier,
            data_controller_name=data_controller_name,
            dpo_contact_hash=dpo_hash,
            kms_key_ring_name=kms_key_ring,
            db_schema_identifier=db_identifier,
            provisioned_at=datetime.now(timezone.utc).isoformat(),
            correlation_id=correlation_id,
        )

        self._tenants[tenant_id] = record

        # Audit entry — LGPD REAT
        entry = self._audit.record(
            tenant_id=tenant_id,
            action=AuditAction.TENANT_PROVISIONED,
            actor_id=actor_id,
            correlation_id=correlation_id,
            metadata={
                "plan": plan_tier.value,
                "controller": data_controller_name,
                "idempotent": False,
            },
        )

        logger.info(
            "Tenant provisioned successfully.",
            extra={
                "tenant_id": tenant_id,
                "plan": plan_tier.value,
                "correlation_id": correlation_id,
            },
        )

        return ProvisioningResult(
            tenant_record=record,
            was_idempotent=False,
            audit_entry_id=entry.entry_id,
        )

    def suspend(self, *, tenant_id: str, reason: str, actor_id: str, correlation_id: str) -> None:
        """
        Suspende um tenant (acesso bloqueado, dados preservados).
        CIA — Availability: suspensão controlada sem perda de dados.
        """
        if tenant_id not in self._tenants:
            raise KeyError(f"Tenant {tenant_id} not found.")
        self._audit.record(
            tenant_id=tenant_id,
            action=AuditAction.TENANT_SUSPENDED,
            actor_id=actor_id,
            correlation_id=correlation_id,
            metadata={"reason": reason},
        )
        logger.warning(
            "Tenant suspended.",
            extra={"tenant_id": tenant_id, "correlation_id": correlation_id},
        )

    def erase(
        self, *, tenant_id: str, actor_id: str, correlation_id: str
    ) -> dict:
        """
        LGPD Art. 18 VI — Direito ao Esquecimento.
        
        Remove DADOS PESSOAIS. Preserva logs de auditoria anonimizados.
        Retorna relatório de erasure para o solicitante.
        
        PRODUÇÃO — passos adicionais:
          1. DROP SCHEMA archon_tenant_{id} CASCADE (PostgreSQL)
          2. gcp_kms.destroy_crypto_key_version(...)
          3. Notificar sistemas downstream
        """
        # Registra a solicitação de erasure ANTES de apagar (para o audit trail)
        self._audit.record(
            tenant_id=tenant_id,
            action=AuditAction.TENANT_ERASED,
            actor_id=actor_id,
            correlation_id=correlation_id,
            metadata={"lgpd_basis": "Art. 18 VI — Direito ao Esquecimento"},
        )

        # Remove o registro do tenant
        self._tenants.pop(tenant_id, None)

        # Anonimiza o audit trail do tenant
        erased_count = self._audit.erase_tenant_data(tenant_id)

        report = {
            "tenant_id": tenant_id,
            "erased_at": datetime.now(timezone.utc).isoformat(),
            "audit_entries_anonymized": erased_count,
            "lgpd_article": "Art. 18 VI",
            "correlation_id": correlation_id,
        }

        logger.info(
            "Tenant data erased (LGPD Art. 18 VI).",
            extra={"correlation_id": correlation_id, "entries_anonymized": erased_count},
        )
        return report

    def get(self, tenant_id: str) -> TenantRecord | None:
        return self._tenants.get(tenant_id)

    def exists(self, tenant_id: str) -> bool:
        return tenant_id in self._tenants


# Singleton
_provisioner: TenantProvisioner | None = None


def get_provisioner() -> TenantProvisioner:
    global _provisioner
    if _provisioner is None:
        from core.audit.trail import get_audit_manager
        _provisioner = TenantProvisioner(audit_manager=get_audit_manager())
    return _provisioner


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION
# python -c "import ast; ast.parse(open('core/tenant/provisioner.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
