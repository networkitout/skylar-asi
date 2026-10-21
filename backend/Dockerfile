FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (DejaVu gives the exports a real bold face for the wordmark)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory and a non-root user that owns the app; running as
# root would make a container compromise a root compromise
RUN mkdir -p /app/data \
    && useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run the application.
# --proxy-headers + --forwarded-allow-ips lets the app trust the
# X-Forwarded-For set by the nginx frontend, so rate limiting is per-client
# and audit logs record the real client IP (only nginx can reach this port).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
