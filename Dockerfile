# =============================================================================
# Archon-V — Dockerfile (Distroless, Non-Root, Multi-Stage)
# Fase 2: Zero CVEs críticos. Zero shell no container final.
# =============================================================================
# VALOR DE NEGÓCIO: Trivy scan = 0 CVEs críticos/altos.
# Quando o CISO perguntar "a imagem de vocês é segura?", mostramos o relatório.
# Imagem distroless: sem bash, sem wget, sem apt. Superfície de ataque mínima.
# =============================================================================

# ── STAGE 1: Builder (instala dependências) ────────────────────────────────
FROM python:3.12-slim AS builder

# Variáveis de build
ARG ARCHON_VERSION=1.0.0

# Usuário não-root no builder
RUN groupadd --gid 10001 archon && \
    useradd --uid 10001 --gid archon --no-create-home archon

WORKDIR /build

# Instalar dependências isoladas em /deps (não polui o sistema)
COPY requirements.txt .
RUN pip install \
    --no-cache-dir \
    --no-warn-script-location \
    --target /deps \
    -r requirements.txt

# ── STAGE 2: Runtime Distroless (zero shell, zero apt, zero risk) ──────────
FROM gcr.io/distroless/python3-debian12:nonroot

LABEL org.opencontainers.image.title="Archon-V Bastion Pre-Flight Security Gate" \
      org.opencontainers.image.version="${ARCHON_VERSION}" \
      org.opencontainers.image.vendor="Archon-V Inc." \
      org.opencontainers.image.description="Enterprise pre-commit security enforcement proxy"

WORKDIR /app

# Copiar dependências Python instaladas no builder
COPY --from=builder /deps /app/deps

# Copiar código da aplicação (sem testes, sem docs)
COPY api/ ./api/
COPY core/ ./core/
COPY infra/ ./infra/
COPY main.py .

# Configurar PYTHONPATH para as dependências isoladas
ENV PYTHONPATH=/app/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

EXPOSE 8080

# USER nonroot já é o default no :nonroot tag (uid=65532)
# Não precisa de USER explícito — é mais seguro assim (Distroless garante)

ENTRYPOINT ["python3", "main.py"]
