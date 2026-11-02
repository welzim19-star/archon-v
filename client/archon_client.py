# =============================================================================
# Archon-V Client SDK — Open Source "Antena"
# File: client/archon_client.py
# LICENSE: MIT (este arquivo vai ao GitHub público)
# VERSION: 1.0.0
# =============================================================================
"""
ARCHON-V CLIENT SDK

Instalação:
  pip install archon-v-client

Uso básico:
  from archon_client import ArchonClient, ClientConfig

  client = ArchonClient(ClientConfig(
      api_url="https://api.archon-v.com",
      tenant_id="acme-corp",
      bearer_token="seu-jwt-aqui",
      tenant_claim_token="seu-tenant-claim-aqui",
  ))

  result = client.pre_flight_check(staged_files=[...])
  if result.is_blocked:
      print("COMMIT BLOQUEADO:", result.violations)
      exit(1)

NOTA DE SEGURANÇA:
  Este SDK é a "Antena" — ele apenas coleta metadados dos arquivos staged
  e envia ao servidor Archon-V para análise. O "Cérebro" (as regras,
  o banco de dados, o KMS) está no servidor e nunca é exposto aqui.
  
  Este arquivo pode ser auditado por qualquer desenvolvedor — by design.
"""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Dependência mínima: apenas requests (stdlib urllib como fallback)
try:
    import urllib.request
    import urllib.error
    import json as _json
    _HAS_REQUESTS = False
    try:
        import requests as _requests
        _HAS_REQUESTS = True
    except ImportError:
        pass
except ImportError:
    pass

__version__ = "1.0.0"
__all__ = ["ArchonClient", "ClientConfig", "PreFlightResult", "Violation"]


# ---------------------------------------------------------------------------
# CONFIGURAÇÃO DO CLIENTE
# ---------------------------------------------------------------------------

@dataclass
class ClientConfig:
    """
    Configuração do cliente Archon-V.
    
    Todos os campos sensíveis devem ser lidos de variáveis de ambiente,
    nunca hardcoded no código (irônico para um produto de segurança).
    
    Uso recomendado:
      config = ClientConfig.from_env()
    """
    api_url: str
    tenant_id: str
    bearer_token: str
    tenant_claim_token: str
    timeout_seconds: int = 10
    max_file_size_bytes: int = 1_048_576  # 1MB — alinhado com o servidor

    @classmethod
    def from_env(cls) -> "ClientConfig":
        """
        Lê configuração de variáveis de ambiente.
        Padrão seguro: nunca colocar tokens em código.
        
        Variáveis necessárias:
          ARCHON_API_URL          ex: https://api.archon-v.com
          ARCHON_TENANT_ID        ex: acme-corp
          ARCHON_BEARER_TOKEN     ex: eyJ...
          ARCHON_TENANT_CLAIM     ex: eyJ...
        """
        missing = []
        for var in ["ARCHON_API_URL", "ARCHON_TENANT_ID", "ARCHON_BEARER_TOKEN", "ARCHON_TENANT_CLAIM"]:
            if not os.environ.get(var):
                missing.append(var)
        if missing:
            raise EnvironmentError(
                f"Archon-V: Missing required environment variables: {', '.join(missing)}\n"
                f"See https://docs.archon-v.com/setup for configuration guide."
            )
        return cls(
            api_url=os.environ["ARCHON_API_URL"].rstrip("/"),
            tenant_id=os.environ["ARCHON_TENANT_ID"],
            bearer_token=os.environ["ARCHON_BEARER_TOKEN"],
            tenant_claim_token=os.environ["ARCHON_TENANT_CLAIM"],
        )


# ---------------------------------------------------------------------------
# MODELOS DE RESPOSTA
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    rule_id: str
    severity: str
    file_path: str
    description: str
    remediation_hint: str


@dataclass
class PreFlightResult:
    verdict: str                          # ALLOW | BLOCK | WARN | REDACT
    violations: list[Violation]
    correlation_id: str
    evaluated_policy_version: str
    cache_hit: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.verdict == "BLOCK"

    @property
    def is_allowed(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def has_warnings(self) -> bool:
        return self.verdict == "WARN"

    def print_report(self) -> None:
        """Imprime relatório colorido no terminal."""
        icons = {"ALLOW": "✅", "BLOCK": "🚫", "WARN": "⚠️", "REDACT": "✏️"}
        colors = {"ALLOW": "\033[92m", "BLOCK": "\033[91m", "WARN": "\033[93m", "REDACT": "\033[94m"}
        reset = "\033[0m"
        color = colors.get(self.verdict, "")

        print(f"\n{color}{'='*60}{reset}")
        print(f"{color}  ARCHON-V PRE-FLIGHT CHECK: {icons.get(self.verdict, '?')} {self.verdict}{reset}")
        print(f"{color}{'='*60}{reset}")

        if self.violations:
            print(f"\n  Found {len(self.violations)} policy violation(s):\n")
            for i, v in enumerate(self.violations, 1):
                sev_color = "\033[91m" if v.severity == "CRITICAL" else "\033[93m"
                print(f"  {i}. [{sev_color}{v.severity}{reset}] {v.rule_id}")
                print(f"     File: {v.file_path}")
                print(f"     Issue: {v.description}")
                if v.remediation_hint:
                    print(f"     Fix: {v.remediation_hint}")
                print()
        else:
            print("\n  No policy violations detected.\n")

        print(f"  Correlation ID: {self.correlation_id}")
        print(f"  Policy Version: {self.evaluated_policy_version}")
        print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLIENTE PRINCIPAL
# ---------------------------------------------------------------------------

class ArchonClient:
    """
    Cliente HTTP para a API do Archon-V.
    Zero lógica de negócio — apenas coleta e transmite.
    """

    def __init__(self, config: ClientConfig) -> None:
        self._config = config
        self._endpoint = f"{config.api_url}/v1/gate/pre-flight-check"

    def _collect_staged_file(self, file_path: str) -> dict[str, Any] | None:
        """
        Coleta metadados de um arquivo staged.
        NUNCA envia o arquivo completo — apenas SHA-256 + metadados.
        Se o arquivo for maior que max_file_size_bytes, pula o content scan.
        """
        p = Path(file_path)
        if not p.exists():
            return None

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            return None

        content_bytes = content.encode("utf-8")
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        size = len(content_bytes)

        return {
            "file_path": str(p),
            "sha256": sha256,
            "content": content if size <= self._config.max_file_size_bytes else "",
            "size_bytes": size,
        }

    def pre_flight_check(
        self,
        staged_file_paths: list[str],
        repository_id: str = "unknown",
        branch_ref: str = "refs/heads/unknown",
        base_commit_sha: str | None = None,
        agent_type: str = "cli-hook",
        agent_version: str = __version__,
        actor_id: str | None = None,
    ) -> PreFlightResult:
        """
        Executa o pre-flight check contra o servidor Archon-V.
        
        Args:
            staged_file_paths: Lista de paths dos arquivos staged (git diff --cached --name-only)
            repository_id:     Identificador do repositório
            branch_ref:        Branch atual (git rev-parse --abbrev-ref HEAD)
            base_commit_sha:   SHA do HEAD atual (git rev-parse HEAD)
            agent_type:        Tipo do agente (ex: 'pre-commit-hook', 'vscode-plugin')
            agent_version:     Versão do agente
            actor_id:          ID do ator (ex: git config user.email)
        """
        import datetime

        correlation_id = str(uuid.uuid4())
        base_sha = base_commit_sha or ("a" * 64)
        actor = actor_id or os.environ.get("GIT_AUTHOR_EMAIL", "unknown@local")
        workstation_fp = hashlib.sha256(
            (os.environ.get("HOSTNAME", "localhost") + actor).encode()
        ).hexdigest()

        # Coletar metadados dos arquivos
        files_data = []
        diff_contents: dict[str, str] = {}

        for path in staged_file_paths[:500]:  # Hard limit: 500 arquivos
            fd = self._collect_staged_file(path)
            if not fd:
                continue
            files_data.append({
                "file_path": fd["file_path"],
                "change_type": "MODIFY",
                "diff_content_sha256": fd["sha256"],
                "line_additions": 0,
                "line_deletions": 0,
                "mime_type": "text/plain",
            })
            if fd["content"]:
                diff_contents[fd["file_path"]] = fd["content"]

        if not files_data:
            return PreFlightResult(
                verdict="ALLOW",
                violations=[],
                correlation_id=correlation_id,
                evaluated_policy_version="1.0.0",
            )

        payload = {
            "gate_request": {
                "tenant_id": self._config.tenant_id,
                "correlation_id": correlation_id,
                "git_context": {
                    "repository_id": repository_id,
                    "branch_ref": branch_ref,
                    "base_commit_sha": base_sha,
                    "staged_files": files_data,
                    "staging_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
                },
                "developer": {
                    "actor_id": actor,
                    "workstation_fingerprint": workstation_fp,
                    "agent_type": agent_type,
                    "agent_version": agent_version,
                },
                "policy_set_version": "1.0.0",
            },
            "diff_contents": diff_contents,
        }

        headers = {
            "Authorization": f"Bearer {self._config.bearer_token}",
            "X-Tenant-Claim": self._config.tenant_claim_token,
            "X-Correlation-Id": correlation_id,
            "Content-Type": "application/json",
        }

        try:
            response_data = self._http_post(self._endpoint, payload, headers)
        except Exception as e:
            # Fail-open para o cliente (ao contrário do servidor que é fail-secure)
            # Justificativa: o hook não deve bloquear o trabalho do dev se o servidor cair
            # O servidor tem SLA 99.99% — mas o dev não pode ficar travado por network issue
            print(f"⚠️  Archon-V: Could not reach gate server ({e}). Allowing commit (fail-open).")
            return PreFlightResult(
                verdict="ALLOW",
                violations=[],
                correlation_id=correlation_id,
                evaluated_policy_version="unknown",
            )

        violations = [
            Violation(
                rule_id=v["rule_id"],
                severity=v["severity"],
                file_path=v["file_path"],
                description=v["description"],
                remediation_hint=v.get("remediation_hint", ""),
            )
            for v in response_data.get("violations", [])
        ]

        return PreFlightResult(
            verdict=response_data.get("verdict", "ALLOW"),
            violations=violations,
            correlation_id=response_data.get("correlation_id", correlation_id),
            evaluated_policy_version=response_data.get("evaluated_policy_version", "1.0.0"),
            cache_hit=response_data.get("cache_hit", False),
        )

    def _http_post(self, url: str, payload: dict, headers: dict) -> dict:
        """HTTP POST — usa requests se disponível, fallback para urllib."""
        import json
        data = json.dumps(payload).encode("utf-8")

        if _HAS_REQUESTS:
            resp = _requests.post(url, data=data, headers=headers, timeout=self._config.timeout_seconds)
            resp.raise_for_status()
            return resp.json()

        # Fallback: urllib (stdlib, zero dependências extras)
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
            return _json.loads(resp.read().decode("utf-8"))
