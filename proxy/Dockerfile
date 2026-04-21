FROM python:3.12-slim

WORKDIR /app

# System deps: libgomp for LightGBM/sklearn, curl for healthchecks/diagnostics
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY config.yaml .
COPY src/ src/

# Create data directory
RUN mkdir -p /data/ollama-proxy

ENV CONFIG_PATH=/app/config.yaml
ENV CACHE_DB=/data/ollama-proxy/cache.db
ENV PYTHONUNBUFFERED=1

EXPOSE 11435

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "11435", "--log-level", "info"]
