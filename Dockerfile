FROM python:3.15-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=Europe/Stockholm
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap avahi-utils docker.io util-linux iproute2 ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/cloudflare/ /app/cloudflare/
COPY src/network-inventory/ /app/network-inventory/
COPY controller.py backup.py /app/
RUN pip install --no-cache-dir -r /app/cloudflare/requirements.txt
CMD ["python", "/app/controller.py"]
