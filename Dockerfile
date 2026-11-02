FROM docker:29-cli AS docker-cli

FROM python:3.15-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=Europe/Stockholm
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap avahi-utils util-linux iproute2 ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
RUN docker --version
WORKDIR /app
COPY src/cloudflare/ /app/cloudflare/
COPY src/network-inventory/ /app/network-inventory/
COPY controller.py backup.py /app/
RUN pip install --no-cache-dir -r /app/cloudflare/requirements.txt
CMD ["python", "/app/controller.py"]
