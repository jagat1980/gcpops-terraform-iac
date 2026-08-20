# Multi-stage Dockerfile for OneShield Vulnerability Engine Gateway
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies & upgrade OS packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Upgrade setuptools and wheel
RUN pip install --no-cache-dir --upgrade setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Final runtime image
FROM python:3.11-slim

WORKDIR /app

# Upgrade Debian OS base packages & Python core build tools
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Force upgrade setuptools & wheel in runtime and purge legacy pre-installed dist-info metadata
RUN pip install --no-cache-dir --upgrade setuptools wheel && \
    rm -rf /usr/local/lib/python3.11/site-packages/wheel-0.45.1* \
           /usr/local/lib/python3.11/site-packages/setuptools/_vendor/jaraco/context.py \
           /usr/local/lib/python3.11/site-packages/setuptools/_vendor/jaraco.context*

COPY app/ ./app/
COPY docs/ ./docs/
COPY scripts/ ./scripts/
COPY README.md .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
