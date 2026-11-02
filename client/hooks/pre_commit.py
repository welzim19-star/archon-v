#!/usr/bin/env python3
# =============================================================================
# Archon-V — Git Pre-Commit Hook
# File: client/hooks/pre_commit.py
# LICENSE: MIT (open-source — vai ao GitHub público)
# =============================================================================
"""
GIT PRE-COMMIT HOOK — ARCHON-V BASTION GATE

Instalação automática (via pip install archon-v-client):
  archon-v install-hook

Instalação manual:
  cp pre_commit.py .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit

Configuração (via variáveis de ambiente no shell ou .archon-v.env):
  export ARCHON_API_URL="https://api.archon-v.com"
  export ARCHON_TENANT_ID="minha-empresa"
  export ARCHON_BEARER_TOKEN="eyJ..."
  export ARCHON_TENANT_CLAIM="eyJ..."

O que este hook faz:
  1. Lista os arquivos staged (git diff --cached --name-only)
  2. Envia metadados + SHA-256 ao servidor Archon-V
  3. Se ALLOW: commit prossegue normalmente
  4. Se BLOCK: commit é ABORTADO e as violações são exibidas
  5. Se WARN:  commit prossegue mas o relatório é exibido
  6. Se servidor indisponível: fail-open (commit prossegue com aviso)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _get_staged_files() -> list[str]:
    """Retorna lista de arquivos staged no git. O(n) onde n = arquivos staged."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


def _get_git_meta() -> dict[str, str]:
    """Coleta metadados do repositório git."""
    def _run(cmd: list[str]) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            return ""

    return {
        "repository_id": _run(["git", "config", "--get", "remote.origin.url"]) or "local",
        "branch_ref": f"refs/heads/{_run(['git', 'rev-parse', '--abbrev-ref', 'HEAD']) or 'unknown'}",
        "base_commit_sha": _run(["git", "rev-parse", "HEAD"]) or "a" * 64,
        "actor_id": _run(["git", "config", "--get", "user.email"]) or "unknown@local",
    }


def main() -> int:
    """
    Ponto de entrada do hook.
    Retorna 0 (permite commit) ou 1 (aborta commit).
    """
    # Importar SDK — se não estiver instalado, fail-open com instrução
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from archon_client import ArchonClient, ClientConfig
    except ImportError:
        print("⚠️  archon-v-client not installed. Run: pip install archon-v-client")
        print("⚠️  Allowing commit (fail-open).")
        return 0

    # Coletar arquivos staged
    staged = _get_staged_files()
    if not staged:
        return 0  # Nada staged — commit vazio, deixa passar

    print(f"\n🛡️  Archon-V Pre-Flight Check — scanning {len(staged)} file(s)...")

    # Carregar configuração
    try:
        config = ClientConfig.from_env()
    except EnvironmentError as e:
        print(f"\n⚠️  {e}")
        print("⚠️  Allowing commit (fail-open — configure ARCHON_* env vars).")
        return 0

    # Executar o check
    meta = _get_git_meta()
    client = ArchonClient(config)

    result = client.pre_flight_check(
        staged_file_paths=staged,
        repository_id=meta["repository_id"],
        branch_ref=meta["branch_ref"],
        base_commit_sha=meta["base_commit_sha"] if len(meta["base_commit_sha"]) == 64 else "a" * 64,
        agent_type="pre-commit-hook",
        actor_id=meta["actor_id"],
    )

    result.print_report()

    if result.is_blocked:
        print("🚫 Commit ABORTED by Archon-V. Fix the violations above and try again.\n")
        return 1  # Aborta o commit

    if result.has_warnings:
        print("⚠️  Commit allowed with warnings. Review the report above.\n")

    return 0  # Permite o commit


if __name__ == "__main__":
    sys.exit(main())
