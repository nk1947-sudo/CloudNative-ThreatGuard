# ThreatGuard metrics exporter image.
# Dependencies are installed at build time, so starting the container needs no
# package download (the previous Compose command ran pip on every start).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    THREATGUARD_PROJECT_ROOT=/workspace \
    THREATGUARD_ARTIFACTS_DIR=/workspace/artifacts

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /build

# Evidence is mounted read-only at /workspace/artifacts by docker-compose.
WORKDIR /workspace
USER 10001:10001
EXPOSE 9100

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9100/healthz', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "cloudnative_threatguard.observability.metrics_exporter"]
