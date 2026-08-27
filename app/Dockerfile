# Multi-stage hardened build for CloudNative ThreatGuard
# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /app
COPY src/requirements.txt .

RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Minimal hardened runtime image
FROM python:3.12-slim AS runtime

# Create non-root system user and group
RUN groupadd -g 10001 threatguard && \
    useradd -u 10001 -g threatguard -s /bin/false -M -d /nonexistent threatguard

WORKDIR /app

# Copy python packages and app code
COPY --from=builder /root/.local /home/threatguard/.local
COPY src/app.py .

# Fix permissions
RUN chown -R threatguard:threatguard /app /home/threatguard/.local

# Set environment
ENV PATH="/home/threatguard/.local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"]

ENTRYPOINT ["python", "app.py"]
