FROM docker:29-cli AS docker-cli

FROM python:3.15-slim
ARG YGGFLARE_BUILD_VERSION=dev
ARG YGGFLARE_BUILD_REVISION=unknown
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC PYTHONPATH=/app:/app/cloudflare
ENV YGGFLARE_BUILD_VERSION=${YGGFLARE_BUILD_VERSION} \
    YGGFLARE_BUILD_REVISION=${YGGFLARE_BUILD_REVISION}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap arp-scan ndisc6 avahi-utils lldpd p0f smbclient samba-common-bin snmp util-linux iproute2 ca-certificates tzdata git \
    && rm -rf /var/lib/apt/lists/*
# nmblookup is provided by samba-common-bin, not smbclient.
RUN command -v nmblookup && command -v smbclient && command -v rdisc6 \
    && test -r /usr/share/nmap/nmap-services
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
RUN docker --version
WORKDIR /app
COPY src/cloudflare/ /app/cloudflare/
COPY src/network_inventory/ /app/network-inventory/
COPY src/yggflare/ /app/
COPY --chmod=755 src/yggflare/cli.py /usr/local/bin/yggflare
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore -r /app/requirements.txt
RUN python -c 'import metrics, web, mcp_server, mcp_http; mcp_server.build_server(); mcp_http.build_http_app(mcp_http.settings({}), b"a" * 64)'
HEALTHCHECK --interval=60s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import os,time; p='/data/heartbeat'; assert os.path.isfile(p) and time.time()-os.stat(p).st_mtime < 300"]

CMD ["python", "/app/controller.py"]
