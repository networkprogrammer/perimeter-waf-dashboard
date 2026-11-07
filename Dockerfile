# Pinned by digest for reproducible builds. Refresh with: docker buildx imagetools inspect python:3.12-slim
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
LABEL org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    AWS_EC2_METADATA_V1_DISABLED=true \
    WAF_DATA_DIR=/data
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY requirements.txt /tmp/requirements.txt
RUN pip install --require-hashes --only-binary :all: -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY app/ /app/
COPY LICENSE /usr/share/licenses/waf-dashboard/LICENSE
USER 10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
# One worker on purpose: the ingest loops and SSE fan-out live in this process.
# Client addresses from X-Forwarded-For are trusted only from FORWARDED_ALLOW_IPS (uvicorn default 127.0.0.1).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-server-header", "--timeout-keep-alive", "30", "--proxy-headers"]
