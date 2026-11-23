#!/bin/sh
# Writes Prometheus's configuration from .env at start-up, then starts it.
# Onshore's metrics are read through the edge's internal listener with a metrics key (Health & alerts,
# Metrics, Create key) set as RV_METRICS_KEY in .env.
set -eu
host="${RV_HOST:-localhost}"
umask 077
printf '%s' "${RV_METRICS_KEY:-}" > /tmp/metrics-key

cat > /tmp/prometheus.yml <<CONF
global:
  scrape_interval: 30s
  external_labels:
    install: ${host}
scrape_configs:
  # Through the edge's internal-only listener, which forwards to the control API
  # over mutual TLS. Nothing outside Docker's internal network can reach it.
  - job_name: onshore
    metrics_path: /v1/monitoring/metrics
    authorization:
      type: Bearer
      credentials_file: /tmp/metrics-key
    static_configs:
      - targets: ["edge:9180"]
  - job_name: loki
    static_configs:
      - targets: ["loki:3100"]
  - job_name: alloy
    static_configs:
      - targets: ["alloy:12345"]
CONF

exec /bin/prometheus \
  --config.file=/tmp/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time="${RV_METRICS_RETENTION:-30d}" \
  --web.external-url=/prometheus/ \
  --web.route-prefix=/
