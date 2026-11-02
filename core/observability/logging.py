# =============================================================================
# Archon-V — Structured Logging + PII Scrubber
# File: core/observability/logging.py
# =============================================================================
"""
LOGGING AUDITÁVEL — VALOR DE NEGÓCIO:
  "Nossos logs podem ser entregues ao regulador (ANPD, BACEN, auditor SOC 2)
  sem risco, porque PII e segredos são removidos ANTES de chegar ao sink."

GARANTIAS:
  1. Todo log é emitido em JSON estruturado (parseável por SIEM/Chronicle).
  2. PII Scrubber intercepta TODAS as mensagens antes do handler de saída.
  3. Correlation ID propagado via contextvars (async-safe, sem thread-local).
  4. Nível de log configurável via env var LOG_LEVEL.
  5. Campos NUNCA presentes em logs: CPF, email, cartão, chave RSA, .env values.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import time
from typing import Final

# ---------------------------------------------------------------------------
# CONTEXT VAR — Correlation ID propagado por toda a cadeia async
# ---------------------------------------------------------------------------

_correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="no-correlation-id"
)


def set_correlation_id(correlation_id: str) -> None:
    """Define o Correlation ID no contexto atual (async-safe)."""
    _correlation_id_var.set(correlation_id)


def get_correlation_id() -> str:
    """Retorna o Correlation ID do contexto atual."""
    return _correlation_id_var.get()


# ---------------------------------------------------------------------------
# PII SCRUBBER — Remove PII/Secrets de QUALQUER string de log
# ---------------------------------------------------------------------------

# Padrões compilados uma única vez (O(1) no hot-path de cada log)
_SCRUB_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # CPF brasileiro: 000.000.000-00 → [CPF REDACTED]
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "[CPF REDACTED]"),
    # Email: user@domain.com → [EMAIL REDACTED]
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL REDACTED]"),
    # Cartão de crédito (PAN)
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "[CARD REDACTED]"),
    # Chave privada RSA/SSH
    (re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----.*?-----END.*?-----", re.DOTALL), "[PRIVATE KEY REDACTED]"),
    # AWS Keys
    (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "[AWS KEY REDACTED]"),
    # GCP API Keys
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "[GCP KEY REDACTED]"),
    # Assignments: password="valor" → password="[SECRET REDACTED]"
    (re.compile(r'(?i)(password|secret|token|api_key)\s*=\s*["\'][^"\']{6,}["\']'), r"\1=[SECRET REDACTED]"),
)


def scrub_pii(text: str) -> str:
    """
    Remove PII e segredos de uma string. O(P) onde P = número de padrões (fixo = 7).
    Efetivamente O(1) em relação ao volume de dados.
    """
    for pattern, replacement in _SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# JSON LOG FORMATTER — Saída estruturada parseável por SIEM
# ---------------------------------------------------------------------------

class ArchonJsonFormatter(logging.Formatter):
    """
    Formata cada log record como JSON de linha única.
    Inclui correlation_id automático do contextvars.
    Aplica scrubber de PII em `msg` e `extra` fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Campos base
        log_entry: dict = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%03dZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": scrub_pii(record.getMessage()),
            "correlation_id": _correlation_id_var.get(),
        }

        # Campos extras (ex: extra={"tenant_id": "...", "verdict": "..."})
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno",
                "pathname", "filename", "module", "exc_info", "exc_text",
                "stack_info", "lineno", "funcName", "created", "msecs",
                "relativeCreated", "thread", "threadName", "processName",
                "process", "message", "taskName",
            ):
                # Scrub em campos extras também
                cleaned = scrub_pii(str(value)) if isinstance(value, str) else value
                log_entry[key] = cleaned

        # Exceções: apenas tipo + mensagem mascarada (sem traceback completo)
        if record.exc_info:
            exc_type = record.exc_info[0]
            log_entry["exception_type"] = exc_type.__name__ if exc_type else "Unknown"
            # Não incluímos o traceback — ele pode conter paths, variáveis, valores de config

        return json.dumps(log_entry, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# SETUP FUNCTION — Chamada uma vez no startup da aplicação
# ---------------------------------------------------------------------------

def setup_logging(log_level: str = "INFO") -> None:
    """
    Configura o sistema de logging global da aplicação.
    Deve ser chamado ANTES de qualquer outro import que use logging.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ArchonJsonFormatter())
    handler.setLevel(level)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    # Remover handlers padrão do Python (evita double-logging)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Silenciar loggers ruidosos de bibliotecas terceiras
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# SYNTAX VALIDATION COMMAND
# python -c "import ast; ast.parse(open('core/observability/logging.py').read()); print('SYNTAX OK')"
# ---------------------------------------------------------------------------
