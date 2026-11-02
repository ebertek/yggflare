FROM docker:29-cli AS docker-cli

FROM python:3.15-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap avahi-utils util-linux iproute2 ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
RUN docker --version
WORKDIR /app
COPY src/cloudflare/ /app/cloudflare/
COPY src/network-inventory/ /app/network-inventory/
COPY controller.py backup.py watchers.py /app/
COPY --chmod=755 cli.py /usr/local/bin/yggflare
RUN pip install --no-cache-dir -r /app/cloudflare/requirements.txt
HEALTHCHECK --interval=60s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import os,time; p='/data/heartbeat'; assert os.path.isfile(p) and time.time()-os.stat(p).st_mtime < 300"]

CMD ["python", "/app/controller.py"]
