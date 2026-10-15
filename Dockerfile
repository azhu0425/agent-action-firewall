# Agent Action Firewall: offline, keyless policy gateway. Build: docker build -t firewall .
# Run: docker run -p 8000:8000 firewall   (evidence/operate.md)

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# Dependencies first, so a code-only change reuses this layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY firewall ./firewall
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home firewall
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY policy ./policy
# The audit log is the only writable path. In production it is a mounted volume (operate.md).
RUN mkdir audit && chown firewall:firewall audit
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FIREWALL_POLICY_PATH=/app/policy/policy.yaml \
    FIREWALL_AUDIT_LOG=/app/audit/audit.jsonl \
    APP_ENV=prod
USER firewall
EXPOSE 8000
# urlopen raises on a non-2xx status, so a degraded /health (no policy loaded) marks the
# container unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
CMD ["uvicorn", "firewall.api:app", "--host", "0.0.0.0", "--port", "8000"]
