# Agent Action Firewall: an offline, keyless policy gateway.
#   docker compose up --build            # API on http://localhost:8000
#   docker compose run --rm verify       # the full strict check suite (what CI runs)
# Targets: `runtime` (the default; slim, non-root) and `verify` (adds dev tools, tests and the eval
# corpus). The README has the full walkthrough.

FROM python:3.12-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

FROM base AS build
# Dependencies first, so a code-only change reuses this layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY firewall ./firewall
RUN uv sync --frozen --no-dev --no-editable

# Dev tools, tests, the eval corpus and the agent guardrails, so `scripts/verify.py --strict`
# runs exactly as in CI with nothing installed on the host.
FROM base AS verify
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --all-extras --no-install-project
COPY . .
RUN uv sync --frozen --all-extras
ENV PATH="/app/.venv/bin:$PATH"
CMD ["python", "scripts/verify.py", "--strict"]

FROM python:3.12-slim AS runtime
RUN useradd --system --uid 10001 --no-create-home firewall
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY policy ./policy
# Read-only inputs for the CLI (demo, replay, examples). The corpus is data, not code.
COPY eval/corpus ./eval/corpus
COPY examples ./examples
# The audit log is the only writable path. Compose mounts a named volume here (operate.md).
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
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
# One worker: the audit hash chain assumes a single writer (decisions.md DR-3).
CMD ["uvicorn", "firewall.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
