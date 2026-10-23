# =============================================================================
# AegisFlow - Cognitive Financial Crime & Cyber-Anomaly Detection Engine
# Production Hardened Multi-Stage Dockerfile (CIS Docker Benchmark & PCI-DSS 4.0)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build & Dependencies Layer
# -----------------------------------------------------------------------------
FROM python:3.10-slim AS builder

WORKDIR /build

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated virtual environment for clean portability
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Minimal Hardened Runtime Layer
# -----------------------------------------------------------------------------
FROM python:3.10-slim AS runtime

# CIS Benchmark: Create dedicated non-root service account with immutable UID
RUN groupadd -g 10001 -r aegisgroup && \
    useradd -u 10001 -r -g aegisgroup -s /sbin/nologin -c "AegisFlow Security Daemon" aegisuser

WORKDIR /app

ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    INFERENCE_SLA_MS=3.5 \
    APP_ENV=production

# Copy built virtual environment from builder stage
COPY --from=builder --chown=root:aegisgroup /venv /venv

# Copy application code with least-privilege permissions
COPY --chown=root:aegisgroup . /app

# Ensure runtime directories exist with strict permissions
# /app is read-only (550), while /tmp and /app/data scratch are writable by aegisuser (770)
RUN mkdir -p /app/data /tmp && \
    chown -R aegisuser:aegisgroup /app/data /tmp && \
    chmod -R 550 /app && \
    chmod -R 770 /app/data /tmp

# Switch to unprivileged non-root user (UID 10001)
USER 10001:10001

EXPOSE 8000

# Native healthcheck using python stdlib (dynamic port aware, zero curl/wget attack surface)
HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, os; port = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=2).read()" || exit 1

# Production ASGI server with dynamic cloud $PORT binding (Render, Railway, Cloud Run, HF Spaces)
CMD ["sh", "-c", "uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2 --timeout-keep-alive 30 --access-log"]

