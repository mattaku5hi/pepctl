# PEPCTL Monitoring Stack Documentation

## Table of Contents
- [Overview](#overview)
- [Why Both Prometheus AND Grafana?](#why-both-prometheus-and-grafana)
- [Architecture](#architecture)
- [Prometheus Setup](#prometheus-setup)
- [Grafana Setup](#grafana-setup)
- [Metrics Explained](#metrics-explained)
- [Dashboards](#dashboards)
- [Alerting](#alerting)
- [Deployment Options](#deployment-options)
- [Troubleshooting](#troubleshooting)

## Overview

PEPCTL's monitoring stack combines **Prometheus** for metrics collection and storage with **Grafana** for visualization and dashboarding. This provides comprehensive observability into packet processing performance, policy effectiveness, and system health.

### Key Benefits
- **Real-time Metrics**: Live monitoring of packet processing
- **Historical Analysis**: Trend analysis and capacity planning
- **Alerting**: Proactive notifications for issues
- **Visual Dashboards**: Intuitive performance visualization
- **Multi-dimensional Data**: Rich labeling and filtering

## Why Both Prometheus AND Grafana?

Many people ask: "Why do we need both tools? Can't one do everything?" Here's the detailed explanation:

### Prometheus: The Data Engine 📊

Prometheus is primarily a **time-series database** and **metrics collection system**:

#### What Prometheus Does
- **Data Collection**: Scrapes metrics from PEPCTL every 15 seconds
- **Time-Series Storage**: Stores metrics with timestamps in efficient format
- **Query Language**: PromQL for complex metric analysis and aggregation
- **Alerting Engine**: Evaluates rules and triggers alerts
- **Data Retention**: Configurable retention periods (default: 15 days)
- **Service Discovery**: Automatically discovers monitoring targets

#### Prometheus Strengths
- ✅ **High Performance**: Optimized for time-series data
- ✅ **Reliability**: Pull-based model, no data loss during restarts
- ✅ **Scalability**: Handles millions of data points
- ✅ **Alerting**: Built-in alert evaluation and routing
- ✅ **Query Power**: Complex aggregations and calculations

#### Prometheus Limitations
- ❌ **Basic UI**: Simple, functional but not visually appealing
- ❌ **Limited Visualization**: Basic graphs only
- ❌ **No Dashboards**: Cannot create comprehensive dashboards
- ❌ **User Experience**: Not designed for end-user consumption

### Grafana: The Visualization Layer 📈

Grafana is a **visualization and dashboarding platform**:

#### What Grafana Does
- **Rich Visualizations**: Graphs, charts, heatmaps, gauges
- **Dashboard Creation**: Combine multiple visualizations
- **User Interface**: Beautiful, intuitive web interface
- **Multi-Data Sources**: Can combine Prometheus with other sources
- **User Management**: Teams, permissions, and access control
- **Templating**: Dynamic dashboards with variables

#### Grafana Strengths
- ✅ **Beautiful UI**: Professional, customizable dashboards
- ✅ **Visualization Variety**: 30+ chart types
- ✅ **Interactive**: Zoom, filter, drill-down capabilities
- ✅ **Sharing**: Export, embed, and share dashboards
- ✅ **Templating**: Dynamic dashboards with variables
- ✅ **Alerting UI**: Visual alert management

#### Grafana Limitations
- ❌ **No Data Storage**: Requires external data sources
- ❌ **No Data Collection**: Cannot gather metrics directly
- ❌ **Query Dependent**: Relies on data source query languages

### Why You Need Both 🤝

```
PEPCTL → Prometheus → Grafana → Operators
   ↓         ↓          ↓
Metrics   Storage   Visualization
```

#### The Partnership
1. **PEPCTL** generates metrics (packets processed, policies applied)
2. **Prometheus** collects and stores these metrics efficiently
3. **Grafana** queries Prometheus and creates beautiful visualizations
4. **Operators** use Grafana dashboards to monitor and troubleshoot

#### Real-World Analogy
Think of it like a restaurant:
- **PEPCTL** = Kitchen (produces the food/metrics)
- **Prometheus** = Storage/Warehouse (preserves and organizes food)
- **Grafana** = Restaurant/Presentation (beautifully serves food to customers)

You need all three components for a complete experience!

## Architecture

### Component Interaction

```
┌─────────────┐    HTTP GET     ┌─────────────┐    PromQL     ┌─────────────┐
│   PEPCTL    │ ──────────────► │ Prometheus  │ ────────────► │   Grafana   │
│ Port 9090   │   /metrics      │ Port 9091   │   Queries     │ Port 3000   │
│             │                 │             │               │             │
│ • Packet    │                 │ • Time      │               │ • Dashboards│
│   Stats     │                 │   Series    │               │ • Alerting  │
│ • Policy    │                 │   Database  │               │ • Users     │
│   Metrics   │                 │ • Alerting  │               │ • Teams     │
│ • eBPF      │                 │ • Rules     │               │             │
│   Data      │                 │             │               │             │
└─────────────┘                 └─────────────┘               └─────────────┘
```

### Data Flow

1. **PEPCTL** exposes metrics at `http://localhost:9090/metrics`
2. **Prometheus** scrapes PEPCTL every 15 seconds
3. **Prometheus** stores metrics in time-series database
4. **Grafana** queries Prometheus using PromQL
5. **Grafana** renders visualizations and dashboards
6. **Alerts** are triggered by Prometheus rules
7. **Notifications** are sent via configured channels

## Prometheus Setup

### Configuration File (prometheus.yml)

```yaml
# Global configuration
global:
  scrape_interval: 15s        # Scrape targets every 15 seconds
  evaluation_interval: 15s    # Evaluate rules every 15 seconds
  external_labels:
    monitor: 'pepctl-monitor'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

# Load rules once and periodically evaluate them
rule_files:
  - "pepctl_rules.yml"

# Scrape configuration
scrape_configs:
  # PEPCTL metrics
  - job_name: 'pepctl'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
    metrics_path: /metrics
    
  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9091']

  # Node exporter (system metrics)
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
```

### Alert Rules (pepctl_rules.yml)

```yaml
groups:
  - name: pepctl_alerts
    rules:
      # High packet drop rate
      - alert: HighPacketDropRate
        expr: rate(pepctl_packets_blocked_total[5m]) / rate(pepctl_packets_processed_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High packet drop rate detected"
          description: "PEPCTL is blocking {{ $value | humanizePercentage }} of packets"

      # PEPCTL daemon down
      - alert: PepctlDaemonDown
        expr: up{job="pepctl"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PEPCTL daemon is down"
          description: "PEPCTL daemon has been down for more than 1 minute"

      # High memory usage
      - alert: HighMemoryUsage
        expr: pepctl_daemon_memory_usage_bytes > 100 * 1024 * 1024  # 100MB
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "PEPCTL high memory usage"
          description: "PEPCTL is using {{ $value | humanizeBytes }} of memory"

      # Policy map full
      - alert: PolicyMapFull
        expr: pepctl_policy_count / pepctl_policy_capacity > 0.9
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Policy map nearly full"
          description: "Policy map is {{ $value | humanizePercentage }} full"
```

### Starting Prometheus

#### Option 1: Binary Installation
```bash
# Download Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*

# Start Prometheus
./prometheus --config.file=../monitoring/prometheus.yml \
              --storage.tsdb.path=./data \
              --web.console.libraries=console_libraries \
              --web.console.templates=consoles \
              --web.listen-address=:9091
```

#### Option 2: Docker
```bash
docker run -d \
  --name prometheus \
  -p 9091:9090 \
  -v $(pwd)/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v $(pwd)/monitoring/pepctl_rules.yml:/etc/prometheus/pepctl_rules.yml \
  prom/prometheus:latest
```

#### Option 3: System Service
```bash
sudo systemctl start pepctl-prometheus
sudo systemctl enable pepctl-prometheus
```

## Grafana Setup

### Installation Options

#### Option 1: APT Repository
```bash
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana
```

#### Option 2: Docker
```bash
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -v grafana-storage:/var/lib/grafana \
  -v $(pwd)/monitoring/grafana/dashboards:/var/lib/grafana/dashboards \
  -v $(pwd)/monitoring/grafana/provisioning:/etc/grafana/provisioning \
  grafana/grafana:latest
```

### Data Source Configuration

Add Prometheus as a data source in Grafana:

```yaml
# provisioning/datasources/prometheus.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9091
    isDefault: true
    editable: true
```

### Starting Grafana

```bash
# System service
sudo systemctl start grafana-server
sudo systemctl enable grafana-server

# Access at http://localhost:3000
# Default login: admin/admin
```

## Metrics Explained

### Core PEPCTL Metrics

#### Packet Processing Metrics
```
# Total packets processed by eBPF
pepctl_packets_processed_total{interface="ens33"}

# Packets allowed through
pepctl_packets_allowed_total{interface="ens33"}

# Packets blocked
pepctl_packets_blocked_total{interface="ens33",reason="policy"}

# Packets rate limited
pepctl_packets_rate_limited_total{interface="ens33"}

# Bytes processed
pepctl_bytes_processed_total{interface="ens33"}
```

#### Policy Engine Metrics
```
# Number of active policies
pepctl_policy_count

# Policy capacity
pepctl_policy_capacity

# Policy lookups per second
rate(pepctl_policy_lookups_total[1m])

# Policy map updates
pepctl_policy_updates_total
```

#### eBPF Performance Metrics
```
# eBPF program status (1=loaded, 0=not loaded)
pepctl_ebpf_program_loaded

# Average program execution time
pepctl_ebpf_program_runtime_ns

# Map lookup failures
pepctl_ebpf_map_lookup_failures_total

# Per-CPU statistics
pepctl_ebpf_stats_per_cpu{cpu="0",stat="packets_total"}
```

#### System Metrics
```
# Daemon uptime
pepctl_uptime_seconds

# Memory usage
pepctl_daemon_memory_usage_bytes

# CPU usage
pepctl_daemon_cpu_usage_percent

# Admin API requests
pepctl_admin_requests_total{method="GET",endpoint="/api/v1/policies"}
```

### Useful PromQL Queries

#### Packet Processing Rate
```promql
# Packets per second
rate(pepctl_packets_processed_total[1m])

# Block rate percentage
rate(pepctl_packets_blocked_total[1m]) / rate(pepctl_packets_processed_total[1m]) * 100
```

#### Performance Analysis
```promql
# Top policy lookup rate
topk(5, rate(pepctl_policy_lookups_total[5m]))

# Memory growth rate
deriv(pepctl_daemon_memory_usage_bytes[10m])

# 95th percentile processing time
histogram_quantile(0.95, rate(pepctl_processing_duration_seconds_bucket[5m]))
```

#### Capacity Planning
```promql
# Policy map utilization
pepctl_policy_count / pepctl_policy_capacity * 100

# Network interface utilization
rate(pepctl_bytes_processed_total[1m]) * 8  # Convert to bits/sec
```

## Dashboards

### PEPCTL Overview Dashboard

Key panels for executive overview:

1. **Traffic Overview**
   - Total packets/second
   - Allowed vs blocked ratio
   - Bytes processed

2. **Security Metrics**
   - Blocked packets by source IP
   - Top blocked ports
   - Attack patterns

3. **Performance Indicators**
   - eBPF processing latency
   - Memory usage
   - CPU utilization

4. **System Health**
   - Daemon uptime
   - eBPF program status
   - Policy count

### Technical Deep-Dive Dashboard

Detailed metrics for engineers:

1. **eBPF Performance**
   - Per-CPU statistics
   - Map operation latencies
   - Program execution time

2. **Policy Engine**
   - Policy lookup performance
   - Map utilization
   - Update frequency

3. **Network Analysis**
   - Protocol distribution
   - Port usage statistics
   - Geographic analysis

### Dashboard JSON Export

```bash
# Export dashboard from Grafana
curl -X GET \
  'http://admin:admin@localhost:3000/api/dashboards/uid/pepctl-overview' \
  -H 'Content-Type: application/json' > pepctl-dashboard.json

# Import dashboard to Grafana
curl -X POST \
  'http://admin:admin@localhost:3000/api/dashboards/db' \
  -H 'Content-Type: application/json' \
  -d @pepctl-dashboard.json
```

## Alerting

### Prometheus Alertmanager

#### Configuration (alertmanager.yml)
```yaml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'pepctl-alerts@company.com'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    email_configs:
      - to: 'admin@company.com'
        subject: 'PEPCTL Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}
    
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#pepctl-alerts'
        title: 'PEPCTL Alert'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
```

### Grafana Alerting

Grafana can also generate alerts based on dashboard queries:

1. **Create Alert Rule**
   - Navigate to dashboard panel
   - Click "Alert" tab
   - Define query and thresholds
   - Configure notification channels

2. **Notification Channels**
   - Email
   - Slack
   - PagerDuty
   - Webhook
   - Microsoft Teams

## Deployment Options

### Option 1: Docker Compose (Recommended)

Create `monitoring/docker-compose.yml`:

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: pepctl-prometheus
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./pepctl_rules.yml:/etc/prometheus/pepctl_rules.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana:latest
    container_name: pepctl-grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=pepctl123
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-worldmap-panel

  alertmanager:
    image: prom/alertmanager:latest
    container_name: pepctl-alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml

volumes:
  prometheus_data:
  grafana_data:
```

#### Start the Stack
```bash
cd monitoring/
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f grafana
```

### Option 2: System Services

Install as system services for production:

```bash
# Install monitoring stack
sudo cp monitoring/pepctl-prometheus.service /etc/systemd/system/
sudo cp monitoring/pepctl-grafana.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start services
sudo systemctl enable pepctl-prometheus pepctl-grafana
sudo systemctl start pepctl-prometheus pepctl-grafana

# Check status
sudo systemctl status pepctl-prometheus
sudo systemctl status pepctl-grafana
```

### Option 3: Kubernetes

Deploy in Kubernetes cluster:

```yaml
# monitoring/k8s/pepctl-monitoring.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: pepctl-monitoring

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: pepctl-monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: config
          mountPath: /etc/prometheus/
      volumes:
      - name: config
        configMap:
          name: prometheus-config

---
apiVersion: v1
kind: Service
metadata:
  name: prometheus
  namespace: pepctl-monitoring
spec:
  selector:
    app: prometheus
  ports:
  - port: 9090
    targetPort: 9090
  type: LoadBalancer
```

## Troubleshooting

### Common Issues

#### 1. Prometheus Cannot Scrape PEPCTL
**Symptoms:**
- Target shows as "DOWN" in Prometheus
- No PEPCTL metrics in Grafana

**Solutions:**
```bash
# Check PEPCTL metrics endpoint
curl http://localhost:9090/metrics

# Verify Prometheus configuration
promtool check config monitoring/prometheus.yml

# Check Prometheus logs
journalctl -u pepctl-prometheus -f
```

#### 2. Grafana Cannot Connect to Prometheus
**Symptoms:**
- "Data source proxy error" in Grafana
- No data in dashboards

**Solutions:**
```bash
# Test Prometheus from Grafana container
docker exec grafana curl http://prometheus:9090/api/v1/query?query=up

# Check data source configuration
curl http://admin:admin@localhost:3000/api/datasources
```

#### 3. Missing Metrics
**Symptoms:**
- Some panels show "No data"
- Partial metric availability

**Solutions:**
```bash
# Check metric names in Prometheus
curl http://localhost:9091/api/v1/label/__name__/values | jq

# Verify PEPCTL is exposing metrics
curl http://localhost:9090/metrics | grep pepctl_
```

#### 4. High Memory Usage
**Symptoms:**
- Prometheus consuming too much memory
- Out of memory errors

**Solutions:**
```bash
# Reduce retention period
--storage.tsdb.retention.time=7d

# Increase memory limits
docker run --memory=2g prom/prometheus

# Monitor memory usage
promql: prometheus_tsdb_symbol_table_size_bytes
```

### Performance Optimization

#### Prometheus Tuning
```bash
# Increase scrape interval for high-traffic systems
scrape_interval: 30s

# Reduce series cardinality
# Avoid high-cardinality labels like IP addresses

# Use recording rules for expensive queries
groups:
  - name: pepctl_recording_rules
    rules:
      - record: pepctl:packet_rate_5m
        expr: rate(pepctl_packets_processed_total[5m])
```

#### Grafana Optimization
```bash
# Set query timeout
GF_DATAPROXY_TIMEOUT=60

# Limit concurrent queries
GF_DATAPROXY_MAX_IDLE_CONNECTIONS=100

# Use shorter refresh intervals
refresh: 30s
```

### Health Checks

#### Monitoring Stack Health
```bash
#!/bin/bash
# monitoring/health_check.sh

echo "=== PEPCTL Monitoring Health Check ==="

# Check PEPCTL metrics endpoint
if curl -f http://localhost:9090/metrics >/dev/null 2>&1; then
    echo "✅ PEPCTL metrics endpoint: OK"
else
    echo "❌ PEPCTL metrics endpoint: FAILED"
fi

# Check Prometheus
if curl -f http://localhost:9091/-/healthy >/dev/null 2>&1; then
    echo "✅ Prometheus: OK"
else
    echo "❌ Prometheus: FAILED"
fi

# Check Grafana
if curl -f http://localhost:3000/api/health >/dev/null 2>&1; then
    echo "✅ Grafana: OK"
else
    echo "❌ Grafana: FAILED"
fi

# Check data flow
targets=$(curl -s http://localhost:9091/api/v1/targets | jq -r '.data.activeTargets[].health')
if echo "$targets" | grep -q "up"; then
    echo "✅ Prometheus scraping: OK"
else
    echo "❌ Prometheus scraping: FAILED"
fi
```

Run health check:
```bash
chmod +x monitoring/health_check.sh
./monitoring/health_check.sh
```

This comprehensive monitoring stack provides complete observability into PEPCTL's performance, security effectiveness, and system health, enabling proactive management and optimization of your network security infrastructure. 