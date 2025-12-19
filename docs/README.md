# PEPCTL Documentation Index

Welcome to the comprehensive PEPCTL documentation! This guide will help you understand, deploy, and operate PEPCTL - a high-performance Policy Enforcement Point daemon using eBPF technology.

## 📚 Documentation Structure

### Core Architecture & Design
- **[Project Overview](PROJECT_OVERVIEW.md)** - High-level architecture and design principles
- **[Project Structure](PROJECT_STRUCTURE.md)** - Codebase organization and module breakdown
- **[eBPF Internals](EBPF_INTERNALS.md)** - Deep dive into eBPF processing, maps, and kernel interaction
- **[Policy Engine](POLICY_ENGINE_DETAILED.md)** - Policy matching, evaluation, and performance optimization

### API & Administration
- **[Admin API](ADMIN_API.md)** - Complete REST API reference for policy management
- **[Monitoring Stack](MONITORING_STACK.md)** - Prometheus, Grafana setup and why you need both
- **[Metrics Server Architecture](METRICS_SERVER_ARCHITECTURE.md)** - Internal metrics implementation

### Testing & Quality
- **[Test Suites](TEST_SUITES.md)** - Unit, integration, and E2E testing overview
- **[E2E Testing Scenarios](E2E_TESTING_SCENARIOS.md)** - Real-world testing scenarios and network setups
- **[E2E Implementation](E2E_IMPLEMENTATION_SUMMARY.md)** - Technical implementation of E2E tests

### Development & Build
- **[eBPF CMake Integration](EBPF_CMAKE_INTEGRATION.md)** - Building eBPF programs with CMake
- **[Modern eBPF Headers](MODERN_EBPF_HEADERS.md)** - Using modern eBPF development practices
- **[BTF Explained](BTF_EXPLAINED.md)** - BPF Type Format and debugging
- **[BTF Generation](BTF_GENERATION_EXPLAINED.md)** - Generating BTF information
- **[Coding Style](CODING_STYLE.md)** - Code style guidelines and best practices

### System Integration
- **[SystemD Service](PEPCTL_SYSTEMD_SERVICE_COMPLETE.md)** - Complete systemd integration guide
- **[Process Monitoring](PROCESS_MONITORING.md)** - System monitoring and performance analysis
- **[Logger Architecture](LOGGER_ARCHITECTURE.md)** - Logging system design and usage

### eBPF Deep Dive
- **[Traditional vs VMLinux Headers](TRADITIONAL_vs_VMLINUX_HEADERS.md)** - Header management approaches
- **[Detailed eBPF Macros](DETAILED_EXPLANATION_BPF_MACROS_AND_STRUCTURES.md)** - eBPF macro and structure usage
- **[Traditional Headers Problem](ANSWER_TRADITIONAL_HEADERS_PROBLEM.md)** - Legacy header challenges

### Quick Reference
- **[Prometheus Queries](prometheus_queries_guide.md)** - Ready-to-use monitoring queries

## 🚀 Quick Start Guide

### 1. Installation & Setup
```bash
# Install dependencies
./scripts/install_deps.sh

# Build the project (Clang + Ninja via CMake presets)
./scripts/build.sh --debug

# Create Debian package and install
./scripts/package-deb.sh --build
sudo dpkg -i dist/pepctl_*.deb
```

### 2. Verify Installation
```bash
# Check service status
sudo systemctl status pepctl

# Verify HTTP endpoints (served by MetricsServer)
curl http://localhost:9090/health
curl http://localhost:9090/stats
curl http://localhost:9090/metrics
```

### 3. Basic Operations
```bash
# Add policies from a JSON array file
./scripts/manage_policies.sh -u http://localhost:9090 add ./policies/testing.json

# List policies (JSON array)
curl http://localhost:9090/policies

# Monitor live statistics and metrics
curl http://localhost:9090/stats
curl http://localhost:9090/metrics
```

## 🏗️ Architecture Overview

PEPCTL implements a layered architecture combining user-space control with kernel-space packet processing:

```
┌─────────────── User Space ───────────────┐
│ ┌──────────────────────────────┐ ┌──────────┐ │
│ │ MetricsServer (HTTP)         │ │ Policy   │ │
│ │ /metrics /stats /policies    │ │ Engine   │ │
│ │ /health /reset               │ │ (RCU)    │ │
│ └──────────────────────────────┘ └──────────┘ │
│                                             │
│ ┌─────────────────────────────────────────┐ │
│ │        eBPF Manager (Userspace)         │ │
│ └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
                      │
┌─────────────── Kernel Space ─────────────────┐
│ ┌─────────────┐ ┌─────────────────────────┐   │
│ │ XDP Program │ │     eBPF Maps           │   │
│ │ (packet_    │ │ • policy_map (hash)     │   │
│ │  filter.o)  │ │ • stats_map (per-cpu)   │   │
│ │             │ │ • ring_buffer (events)  │   │
│ └─────────────┘ └─────────────────────────┘   │
│                                               │
│            Network Interface                  │
└───────────────────────────────────────────────┘
```

## 🔍 Key Concepts

### eBPF Integration
- **XDP Processing**: High-performance packet filtering at network driver level
- **Policy Maps**: Hash-based O(1) policy lookup in kernel space
- **Statistics Maps**: Per-CPU counters for lock-free performance
- **Ring Buffer**: Asynchronous event communication to userspace

### Policy Management
- **Dynamic Updates**: Add/remove policies without daemon restart
- **Hierarchical Matching**: Exact match → wildcard match → default policy
- **Rate Limiting**: Token bucket implemented in userspace policy engine (bytes per second)
- **Priority System**: Policy precedence based on specificity

### Monitoring Architecture
- **Prometheus**: Time-series database for metrics collection and alerting
- **Grafana**: Visualization platform for dashboards and analytics
- **Real-time Metrics**: Live packet processing statistics
- **Historical Analysis**: Trend analysis and capacity planning

## 🔧 Common Operations

### Policy Management
```bash
# List all policies
curl "http://localhost:9090/policies"

# Get specific policy
curl "http://localhost:9090/policies" | jq '.[] | select(.id == "<policy_id>")'

# Delete policy
# Variant A: delete by query parameter
curl -X DELETE "http://localhost:9090/policies?id=<policy_id>"

# Variant B: delete by JSON body
curl -X DELETE "http://localhost:9090/policies" \
  -H "Content-Type: application/json" \
  -d '{"id":"<policy_id>"}'
```

### System Monitoring
```bash
# Live statistics
curl "http://localhost:9090/stats"

# Health check
curl "http://localhost:9090/health"

# Reset daemon statistics
curl -X POST "http://localhost:9090/reset"
```

### eBPF Debugging
```bash
# Show loaded eBPF programs
sudo bpftool prog show

# Show eBPF maps
sudo bpftool map show

# Dump policy map contents
sudo bpftool map dump name policy_map

# Show network attachments
sudo bpftool net show
```

## 🚨 Troubleshooting

### Service Issues
```bash
# Check service status
sudo systemctl status pepctl

# View logs
journalctl -u pepctl -f

# Restart service
sudo systemctl restart pepctl
```

### eBPF Issues
```bash
# Check if eBPF program is loaded
sudo bpftool prog show | grep packet_filter

# Verify XDP attachment
sudo ip link show | grep xdp

# Check for eBPF errors
dmesg | grep -i bpf
```

### Networking Issues
```bash
# Test metrics endpoint
curl http://localhost:9090/metrics

# Test health/stats endpoints
curl http://localhost:9090/health
curl http://localhost:9090/stats

# Check interface status
ip link show
```

## 📊 Metrics & Alerting

### Key Metrics to Monitor
- `pepctl_packets_processed_total` - Total packets processed
- `pepctl_packets_blocked_total` - Packets blocked by policies
- `pepctl_policy_count` - Number of active policies
- `pepctl_ebpf_program_loaded` - eBPF program status
- `pepctl_uptime_seconds` - Daemon uptime

### Sample Alerts
```yaml
# High block rate
- alert: HighBlockRate
  expr: rate(pepctl_packets_blocked_total[5m]) / rate(pepctl_packets_processed_total[5m]) > 0.1
  
# Daemon down
- alert: PepctlDown
  expr: up{job="pepctl"} == 0
  
# High memory usage
- alert: HighMemoryUsage
  expr: pepctl_daemon_memory_usage_bytes > 100 * 1024 * 1024
```

## 🛠️ Development

### Building from Source
```bash
# Clone repository
git clone <repository-url>
cd pepctl

# Install dependencies
./scripts/install_deps.sh

# Build project
./scripts/build.sh --debug

# Run tests
cmake --build --preset build-debug
ctest --preset test-debug
```

### Development Workflow
```bash
# Format code
./scripts/format-code.sh

# Run linting
./scripts/format-code.sh --fix-tidy

# Run specific tests
./scripts/test.sh unit
sudo ./scripts/test.sh e2e

# Build with coverage
./scripts/build.sh --coverage tests
./scripts/test.sh --coverage
```

## 📈 Performance Tuning

### eBPF Optimization
- Use per-CPU maps for statistics to avoid lock contention
- Minimize policy map lookups in fast path
- Optimize packet parsing for common protocols
- Use appropriate map sizes for workload

### System Optimization
- Pin eBPF maps to avoid reloading
- Use native XDP mode when driver supports it
- Monitor CPU usage and scale accordingly
- Tune network interface parameters

### Monitoring Optimization
- Adjust Prometheus scrape intervals based on traffic
- Use recording rules for expensive queries
- Implement proper alerting thresholds
- Archive old metrics data appropriately

## 🔒 Security Considerations

### Network Security
- Validate all policy inputs
- Implement rate limiting on admin API
- Use proper authentication mechanisms
- Monitor for anomalous traffic patterns

### System Security
- Run with minimal required privileges
- Isolate daemon in containers when possible
- Keep eBPF programs simple and auditable
- Regular security updates and patches

## 📞 Support & Community

### Getting Help
- Check this documentation first
- Review existing issues in the project repository
- Run built-in diagnostics and health checks
- Enable debug logging for troubleshooting

### Contributing
- Follow the coding style guidelines
- Write comprehensive tests for new features
- Update documentation for changes
- Submit pull requests with clear descriptions

## 📄 License

PEPCTL is licensed under the MIT License. See the LICENSE file for details.

---

*This documentation is continuously updated. For the latest information, check the individual documentation files and the project repository.* 