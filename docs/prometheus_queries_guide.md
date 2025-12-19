# 📊 PEPCTL Prometheus Queries Guide

## **Basic Packet Metrics**

### **1. Total Packets Processed**
```promql
pepctl_daemon_packets_processed_total
```

### **2. Allowed Packets**
```promql
pepctl_daemon_packets_allowed_total
```

### **3. Blocked Packets**
```promql
pepctl_daemon_packets_blocked_total
```

### **4. Logged Packets (LOG_ONLY)**
```promql
pepctl_daemon_packets_logged_total
```

### **5. Rate Limited Packets**
```promql
pepctl_daemon_packets_rate_limited_total
```

## **Rate-Based Queries (Packets per Second)**

### **1. Processing Rate**
```promql
rate(pepctl_daemon_packets_processed_total[5m])
```

### **2. Block Rate**
```promql
rate(pepctl_daemon_packets_blocked_total[5m])
```

### **3. Allow Rate**
```promql
rate(pepctl_daemon_packets_allowed_total[5m])
```

## **Percentage Calculations**

### **1. Block Percentage**
```promql
(pepctl_daemon_packets_blocked_total / pepctl_daemon_packets_processed_total) * 100
```

### **2. Allow Percentage**
```promql
(pepctl_daemon_packets_allowed_total / pepctl_daemon_packets_processed_total) * 100
```

## **Difference Calculations**

### **1. Packets Blocked in Last 5 Minutes**
```promql
increase(pepctl_daemon_packets_blocked_total[5m])
```

### **2. Packets Allowed in Last Hour**
```promql
increase(pepctl_daemon_packets_allowed_total[1h])
```

## **System Metrics**

### **1. Active Policies**
```promql
pepctl_policies_total
```

### **2. Uptime**
```promql
pepctl_uptime_seconds
```

### **3. Data Throughput**
```promql
rate(pepctl_data_bytes_total[5m])
```

## **Advanced Queries**

### **1. Traffic Spike Detection (>10 packets/sec)**
```promql
rate(pepctl_daemon_packets_processed_total[1m]) > 10
```

### **2. High Block Rate Alert (>5 blocks/sec)**
```promql
rate(pepctl_daemon_packets_blocked_total[1m]) > 5
```

### **3. Policy Effectiveness (Block vs Allow Ratio)**
```promql
pepctl_daemon_packets_blocked_total / (pepctl_daemon_packets_allowed_total + pepctl_daemon_packets_blocked_total)
```

## **How to Use These Queries**

### **In Prometheus Web UI:**
1. Open: http://localhost:9091
2. Go to "Graph" tab
3. Enter any query above
4. Click "Execute"

### **In Grafana:**
1. Open: http://localhost:3000
2. Create new panel
3. Use these queries as metrics
4. Customize visualization

## **Current Status Check Commands**

### **Via curl (JSON format):**
```bash
curl -s http://127.0.0.1:9090/metrics | grep pepctl_daemon_packets
```

### **Via Prometheus API:**
```bash
curl -s "http://localhost:9091/api/v1/query?query=pepctl_daemon_packets_blocked_total"
```

## **Example: Real-time Monitoring**

To monitor blocked packets in real-time:
```bash
watch -n 1 'curl -s http://127.0.0.1:9090/metrics | grep blocked'
``` 