FROM docker:29-cli AS docker-cli

FROM python:3.15-slim
ARG YGGFLARE_BUILD_VERSION=dev
ARG YGGFLARE_BUILD_REVISION=unknown
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC PYTHONPATH=/app:/app/cloudflare
ENV YGGFLARE_BUILD_VERSION=${YGGFLARE_BUILD_VERSION} \
    YGGFLARE_BUILD_REVISION=${YGGFLARE_BUILD_REVISION}
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap arp-scan ndisc6 avahi-utils lldpd p0f smbclient samba-common-bin snmp util-linux iproute2 ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
# nmblookup is provided by samba-common-bin, not smbclient.
RUN command -v nmblookup && command -v smbclient \
    && test -r /usr/share/nmap/nmap-services
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
RUN docker --version
WORKDIR /app
COPY src/cloudflare/ /app/cloudflare/
COPY src/network-inventory/ /app/network-inventory/
COPY controller.py backup.py backup_verify.py doctor.py discord_webhook.py watchers.py web.py web_views.py metrics.py inventory_view.py inventory_catalog.py docker_inventory.py /app/
COPY --chmod=755 cli.py /usr/local/bin/yggflare
RUN pip install --no-cache-dir -r /app/cloudflare/requirements.txt
RUN python -c 'import metrics, web'
HEALTHCHECK --interval=60s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import os,time; p='/data/heartbeat'; assert os.path.isfile(p) and time.time()-os.stat(p).st_mtime < 300"]

CMD ["python", "/app/controller.py"]
