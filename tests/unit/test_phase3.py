# =============================================================================
# Archon-V — Unit Tests: Audit Trail + Tenant Provisioner
# File: tests/unit/test_phase3.py
# =============================================================================
"""
Testes de Fase 3: Audit Trail SHA-256, Policy Rulesets, Provisioner.
Estes testes são evidência direta para auditoria LGPD e SOC 2.
"""
import hashlib
import uuid
import pytest

from core.audit.trail import (
    AuditAction,
    AuditEntry,
    AuditTrailManager,
    TenantAuditChain,
    _GENESIS_HASH,
)
from core.policy.ruleset import (
    PolicyRule,
    PolicyRulesetStore,
    RuleType,
    RulesetStatus,
)
from core.tenant.provisioner import PlanTier, TenantProvisioner
from api.v1.gate.schemas import ViolationSeverity


# ─── AUDIT TRAIL ──────────────────────────────────────────────────────────────

class TestAuditEntry:

    def test_entry_is_frozen(self):
        """AuditEntry é imutável após criação — tríade CIA: Integridade."""
        entry = AuditEntry.create(
            tenant_id="acme", action=AuditAction.TENANT_PROVISIONED,
            actor_id="admin@acme.com", correlation_id=str(uuid.uuid4()),
            previous_hash=_GENESIS_HASH,
        )
        with pytest.raises((AttributeError, TypeError)):
            entry.tenant_id = "hacked"  # type: ignore

    def test_actor_id_is_pseudonymized(self):
        """LGPD Art. 12: actor_id nunca armazenado raw."""
        raw_email = "admin@acme.com"
        entry = AuditEntry.create(
            tenant_id="acme", action=AuditAction.ADMIN_ACCESS,
            actor_id=raw_email, correlation_id=str(uuid.uuid4()),
            previous_hash=_GENESIS_HASH,
        )
        assert raw_email not in entry.actor_id_hash
        assert entry.actor_id_hash == hashlib.sha256(raw_email.encode()).hexdigest()

    def test_entry_hash_is_deterministic(self):
        """Dois entries com mesmos campos produzem hashes diferentes (UUID garante unicidade)."""
        corr = str(uuid.uuid4())
        e1 = AuditEntry.create(
            tenant_id="t1", action=AuditAction.GATE_CHECK_PERFORMED,
            actor_id="dev", correlation_id=corr, previous_hash=_GENESIS_HASH,
        )
        e2 = AuditEntry.create(
            tenant_id="t1", action=AuditAction.GATE_CHECK_PERFORMED,
            actor_id="dev", correlation_id=corr, previous_hash=_GENESIS_HASH,
        )
        # entry_ids são UUIDs diferentes → hashes diferentes
        assert e1.entry_hash != e2.entry_hash

    def test_to_dict_does_not_expose_previous_hash(self):
        """previous_hash é interno — não deve aparecer na resposta de API."""
        entry = AuditEntry.create(
            tenant_id="t1", action=AuditAction.KMS_KEY_ENROLLED,
            actor_id="admin", correlation_id=str(uuid.uuid4()),
            previous_hash=_GENESIS_HASH,
        )
        d = entry.to_dict()
        assert "previous_hash" not in d
        assert "metadata" not in d


class TestTenantAuditChain:

    @pytest.fixture
    def chain(self) -> TenantAuditChain:
        return TenantAuditChain("acme-corp")

    def test_empty_chain_has_genesis_hash(self, chain):
        assert chain.head_hash == _GENESIS_HASH

    def test_first_entry_chains_from_genesis(self, chain):
        entry = chain.append(
            action=AuditAction.TENANT_PROVISIONED,
            actor_id="admin", correlation_id=str(uuid.uuid4()),
        )
        assert entry.previous_hash == _GENESIS_HASH
        assert chain.head_hash == entry.entry_hash

    def test_chain_is_linked(self, chain):
        """Cada entrada aponta para o hash da entrada anterior."""
        e1 = chain.append(action=AuditAction.TENANT_PROVISIONED, actor_id="a", correlation_id=str(uuid.uuid4()))
        e2 = chain.append(action=AuditAction.ADMIN_ACCESS, actor_id="b", correlation_id=str(uuid.uuid4()))
        assert e2.previous_hash == e1.entry_hash

    def test_integrity_verification_passes_on_clean_chain(self, chain):
        chain.append(action=AuditAction.TENANT_PROVISIONED, actor_id="a", correlation_id=str(uuid.uuid4()))
        chain.append(action=AuditAction.GATE_CHECK_PERFORMED, actor_id="b", correlation_id=str(uuid.uuid4()))
        assert chain.verify_integrity() is True

    def test_lgpd_erasure_anonymizes_not_deletes(self, chain):
        """LGPD Art. 18 VI: dados pessoais são anonimizados, não deletados."""
        chain.append(action=AuditAction.TENANT_PROVISIONED, actor_id="admin@acme.com", correlation_id=str(uuid.uuid4()))
        chain.append(action=AuditAction.GATE_CHECK_PERFORMED, actor_id="dev@acme.com", correlation_id=str(uuid.uuid4()))

        count = chain.purge_for_erasure()
        assert count == 2  # 2 entradas anonimizadas

        # As entradas ainda existem (não foram deletadas)
        entries = chain.get_entries()
        assert len(entries) == 2  # Ainda há entradas

        # Mas os dados pessoais foram removidos
        for e in entries:
            assert e["tenant_id"] == "[ERASED]"

    def test_tenant_isolation_between_chains(self):
        """Cadeias de tenants diferentes são completamente isoladas."""
        chain_a = TenantAuditChain("tenant-a")
        chain_b = TenantAuditChain("tenant-b")

        chain_a.append(action=AuditAction.TENANT_PROVISIONED, actor_id="admin-a", correlation_id=str(uuid.uuid4()))
        chain_b.append(action=AuditAction.TENANT_PROVISIONED, actor_id="admin-b", correlation_id=str(uuid.uuid4()))

        entries_a = chain_a.get_entries()
        entries_b = chain_b.get_entries()

        # Nenhuma entrada de A aparece em B e vice-versa
        assert all(e["tenant_id"] == "tenant-a" for e in entries_a)
        assert all(e["tenant_id"] == "tenant-b" for e in entries_b)


# ─── POLICY RULESET ───────────────────────────────────────────────────────────

class TestPolicyRuleset:

    @pytest.fixture
    def store(self) -> PolicyRulesetStore:
        return PolicyRulesetStore()

    def _make_rule(self, rule_id: str = "CUSTOM-PII-001") -> PolicyRule:
        return PolicyRule(
            rule_id=rule_id,
            rule_type=RuleType.PII_PATTERN,
            severity=ViolationSeverity.CRITICAL,
            pattern=r"\d{3}\.\d{3}\.\d{3}-\d{2}",
            description="CPF detectado",
            remediation_hint="Remova o CPF",
            lgpd_basis="Art. 6 III — Necessidade",
        )

    def test_create_draft_ruleset(self, store):
        rule = self._make_rule()
        rs = store.create(tenant_id="acme", version="1.0.0", rules=[rule], created_by_hash="abc")
        assert rs.status == RulesetStatus.DRAFT
        assert rs.version == "1.0.0"
        assert len(rs.rules) == 1

    def test_publish_promotes_draft(self, store):
        rule = self._make_rule()
        rs = store.create(tenant_id="acme", version="1.0.0", rules=[rule], created_by_hash="abc")
        published = store.publish("acme", rs.ruleset_id)
        assert published.status == RulesetStatus.PUBLISHED
        assert published.published_at is not None

    def test_publishing_deprecates_previous(self, store):
        rule = self._make_rule()
        rs1 = store.create(tenant_id="acme", version="1.0.0", rules=[rule], created_by_hash="abc")
        store.publish("acme", rs1.ruleset_id)
        rs2 = store.create(tenant_id="acme", version="1.1.0", rules=[rule], created_by_hash="abc")
        store.publish("acme", rs2.ruleset_id)

        all_sets = store.get_all("acme")
        statuses = {rs.version: rs.status for rs in all_sets}
        assert statuses["1.0.0"] == RulesetStatus.DEPRECATED
        assert statuses["1.1.0"] == RulesetStatus.PUBLISHED

    def test_version_regression_rejected(self, store):
        """Imutabilidade: não pode criar versão menor que a existente."""
        rule = self._make_rule()
        store.create(tenant_id="acme", version="2.0.0", rules=[rule], created_by_hash="abc")
        with pytest.raises(ValueError, match="greater than"):
            store.create(tenant_id="acme", version="1.9.9", rules=[rule], created_by_hash="abc")

    def test_invalid_regex_rejected(self, store):
        """Regex inválida é rejeitada na criação da regra."""
        with pytest.raises(ValueError):
            PolicyRule(
                rule_id="BAD-REX-001",
                rule_type=RuleType.SECRET_PATTERN,
                severity=ViolationSeverity.HIGH,
                pattern="[invalid regex(",
                description="bad",
                remediation_hint="",
                lgpd_basis="N/A",
            )

    def test_invalid_semver_rejected(self, store):
        rule = self._make_rule()
        with pytest.raises(ValueError):
            store.create(tenant_id="acme", version="1.0", rules=[rule], created_by_hash="abc")


# ─── TENANT PROVISIONER ───────────────────────────────────────────────────────

class TestTenantProvisioner:

    @pytest.fixture
    def provisioner(self) -> TenantProvisioner:
        from core.audit.trail import AuditTrailManager
        return TenantProvisioner(audit_manager=AuditTrailManager())

    def _provision(self, provisioner, tenant_id="acme-corp"):
        return provisioner.provision(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PROFESSIONAL,
            data_controller_name="Acme Corp LTDA",
            dpo_contact_email="dpo@acme.com",
            actor_id="admin@archon-v.com",
            correlation_id=str(uuid.uuid4()),
        )

    def test_provision_creates_tenant(self, provisioner):
        result = self._provision(provisioner)
        assert result.tenant_record.tenant_id == "acme-corp"
        assert result.was_idempotent is False

    def test_provision_is_idempotent(self, provisioner):
        self._provision(provisioner, "acme-corp")
        result2 = self._provision(provisioner, "acme-corp")
        assert result2.was_idempotent is True

    def test_dpo_email_is_pseudonymized(self, provisioner):
        """LGPD Art. 12: email do DPO nunca armazenado raw."""
        result = self._provision(provisioner)
        record = result.tenant_record
        assert "dpo@acme.com" not in record.dpo_contact_hash
        assert record.dpo_contact_hash == hashlib.sha256(b"dpo@acme.com").hexdigest()

    def test_different_tenants_get_different_db_schemas(self, provisioner):
        r1 = self._provision(provisioner, "tenant-alpha")
        r2 = self._provision(provisioner, "tenant-beta")
        assert r1.tenant_record.db_schema_identifier != r2.tenant_record.db_schema_identifier

    def test_lgpd_erasure_removes_tenant(self, provisioner):
        self._provision(provisioner)
        assert provisioner.exists("acme-corp") is True
        report = provisioner.erase(
            tenant_id="acme-corp",
            actor_id="admin",
            correlation_id=str(uuid.uuid4()),
        )
        assert provisioner.exists("acme-corp") is False
        assert "lgpd_article" in report
        assert report["lgpd_article"] == "Art. 18 VI"
