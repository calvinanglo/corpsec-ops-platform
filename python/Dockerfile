# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Python detection/remediation/compliance engine
# ══════════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim

LABEL org.opencontainers.image.title="corpsec-python"
LABEL org.opencontainers.image.description="DLP + AI detection + SOAR + compliance evidence collection"
LABEL org.opencontainers.image.source="https://github.com/calvinanglo/corpsec-ops-platform"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . /app

# Create runtime dirs (compliance evidence, audit logs, jsonl outputs)
RUN mkdir -p /var/log/corpsec /compliance/evidence

# Health endpoint runs on 8080
EXPOSE 8080

# Default: launch the HTTP API for n8n / active-response calls
CMD ["python", "-m", "remediation.api_server"]
