# =============================================================================
# Archon-V — Hardened Production Dockerfile (Python 3.12-slim, Non-Root)
# =============================================================================
# Optimized for cloud deployment (Render, Cloud Run, GKE)
# Sub-150MB footprint, zero ABI mismatch, non-root user execution
# =============================================================================

FROM python:3.12-slim

WORKDIR /app

# Create non-root user for security compliance
RUN groupadd -g 10001 archon && \
    useradd -u 10001 -g archon -s /bin/sh -m archon

# Upgrade pip and install pinned dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY api/ ./api/
COPY core/ ./core/
COPY infra/ ./infra/
COPY main.py .

# Ensure secure ownership
RUN chown -R archon:archon /app

USER archon

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

EXPOSE 8080

CMD ["python", "main.py"]
