# PEPCTL - Policy Enforcement Point Control Utility

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-unit%20%7C%20integration%20%7C%20e2e-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## Overview

PEPCTL is a high-performance Policy Enforcement Point (PEP) daemon built in modern C++ that provides real-time network packet filtering and policy enforcement using eBPF technology. It features comprehensive testing, automated packaging, production-ready deployment tools, and advanced monitoring capabilities.

## Features

### Core Functionality
- **eBPF-Based Packet Processing**: High-performance kernel-space packet filtering using XDP
- **Dynamic Policy Management**: Runtime policy updates without daemon restart
- **Lock-Free Architecture**: Optimized for multi-threaded performance with atomic operations
- **Real-Time Metrics**: HTTP-based metrics server with Prometheus integration
- **Comprehensive Logging**: Structured logging with configurable levels and systemd integration
- **Modern C++20**: Built with modern C++ standards and best practices

### Advanced Features
- **Admin API**: RESTful API for policy management and system monitoring
- **Prometheus Integration**: Native metrics export for monitoring and alerting
- **Grafana Dashboards**: Pre-built dashboards for visualization
- **Systemd Service**: Complete systemd integration with auto-start capability
- **Professional Packaging**: Debian packages with proper dependency management
- **Cross-Platform Support**: Linux kernel 4.15+ with eBPF/XDP support

### Testing & Quality Assurance
- **Comprehensive Test Suites**: Unit, Integration, and End-to-End tests
- **Real Network Testing**: E2E tests with actual client-server communication
- **Network Namespace Isolation**: Single-machine E2E testing without VMs
- **Code Coverage Reports**: Automated coverage analysis with HTML reports
- **Memory Leak Detection**: Valgrind integration for memory safety
- **CI/CD Ready**: Automated testing and deployment pipelines

### Build & Deployment
- **Flexible Build System**: Build all targets or specific components
- **Debian Package Generation**: Professional DEB packages with systemd integration
- **Docker Support**: Container-ready deployment
- **Automated Dependency Management**: Complete dependency installation scripts

## Architecture Overview

PEPCTL implements a multi-layered architecture combining user-space control with kernel-space packet processing:

```
┌─────────────── User Space ───────────────┐
│ ┌─────────────┐ ┌─────────────┐ ┌──────────┐ │
│ │ Admin API │ │ Metrics │ │ Policy │ │
│ │ (Port 8080) │ │ (Port 9090) │ │ Engine └─┐ │
│ └─────────────┘ └─────────────┘ └──────────┘ │
│ │ │ │ │
│ └─────────────────┼─────────────────┘ │
│ │ │
│ ┌─────────────────┐ │
│ │ eBPF Manager │ │ 
│ │ (Userspace) │ │
│ └─────────────────┘ │
└───────────────────────────────────────────┘
│
┌─────────────── Kernel Space ─────────────┐
│ ┌─────────────┐ ┌─────────────┐ │
│ │ XDP Program │ │ eBPF Maps │ │
│ │ (packet_filter)│ │ (Policies) │ │
│ └─────────────┘ └─────────────┘ │
│ │ │
│ Network Interface │
└───────────────────────────────────────────┘
```

## eBPF Internal Architecture

### XDP Processing Pipeline

PEPCTL uses eXpress Data Path (XDP) for high-performance packet processing:

```
Network Packet → NIC Driver → XDP Hook → packet_filter.o → Decision
                                     ↓
                              [PASS|DROP|TX]
```

### eBPF Maps Structure

| Map Name | Type | Purpose | Size |
|----------|------|---------|------|
| `policy_map` | BPF_MAP_TYPE_HASH | Policy storage (IP/Port rules) | 10,000 entries |
| `stats_map` | BPF_MAP_TYPE_PERCPU_ARRAY | Per-CPU packet statistics | 1024 entries |
| `ring_buffer` | BPF_MAP_TYPE_RINGBUF | Event notifications to userspace | 64KB |

### Packet Processing Logic

1. **Packet Arrival**: Network packet hits XDP hook
2. **Header Parsing**: Extract IP/TCP/UDP headers
3. **Policy Lookup**: Hash-based O(1) policy map lookup
4. **Action Decision**: ALLOW/BLOCK/RATE_LIMIT based on policy
5. **Statistics Update**: Atomic counters per-CPU for performance
6. **Event Logging**: Ring buffer notification for blocked packets

## Admin API Reference

### Base URL
```
http://localhost:8080/api/v1/
```

### Policy Management Endpoints

#### Get All Policies
```bash
GET /api/v1/policies
```

#### Add New Policy
```bash
POST /api/v1/policies
Content-Type: application/json

{
  "id": "unique_policy_id",
  "action": "BLOCK|ALLOW|RATE_LIMIT",
  "src_ip": "192.168.1.100",          # Optional
  "dst_ip": "10.0.0.50",              # Optional  
  "src_port": 80,                     # Optional
  "dst_port": 443,                    # Optional
  "protocol": "TCP|UDP|ICMP",         # Optional
  "rate_limit": 1000000,              # Bytes/sec (for RATE_LIMIT)
  "description": "Human readable description"
}
```

#### Update Policy
```bash
PUT /api/v1/policies/{policy_id}
# Same JSON body as POST
```

#### Delete Policy
```bash
DELETE /api/v1/policies/{policy_id}
```

### System Status Endpoints

#### Daemon Status
```bash
GET /api/v1/status
```

#### eBPF Program Status
```bash
GET /api/v1/ebpf/status
```

#### Live Statistics
```bash
GET /api/v1/stats
```

### Example API Usage

```bash
# Block a suspicious IP
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block_attacker_192_168_1_100", 
    "action": "BLOCK",
    "src_ip": "192.168.1.100",
    "description": "Blocked known attacker IP"
  }'

# Rate limit API endpoint
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "rate_limit_api",
    "action": "RATE_LIMIT", 
    "dst_port": 8080,
    "rate_limit": 1000000,
    "description": "Limit API to 1MB/s"
  }'

# Check daemon status
curl http://localhost:8080/api/v1/status
```

## Metrics and Monitoring

### Prometheus Integration

PEPCTL exposes metrics on port 9090 in Prometheus format:

```bash
curl http://localhost:9090/metrics
```

#### Key Metrics

| Metric Name | Type | Description |
|-------------|------|-------------|
| `pepctl_packets_processed_total` | Counter | Total packets processed by eBPF |
| `pepctl_packets_blocked_total` | Counter | Total packets blocked |
| `pepctl_packets_allowed_total` | Counter | Total packets allowed |
| `pepctl_bytes_processed_total` | Counter | Total bytes processed |
| `pepctl_policy_lookups_total` | Counter | Total policy map lookups |
| `pepctl_policy_count` | Gauge | Current number of active policies |
| `pepctl_ebpf_program_loaded` | Gauge | eBPF program load status (1/0) |
| `pepctl_admin_requests_total` | Counter | Admin API requests |
| `pepctl_uptime_seconds` | Counter | Daemon uptime |

### Why Prometheus AND Grafana?

The monitoring stack uses both tools for different purposes:

#### Prometheus (Metrics Storage & Alerting)
- **Time-Series Database**: Stores metrics with timestamps
- **Data Collection**: Scrapes metrics from PEPCTL every 15 seconds
- **Alerting Engine**: Triggers alerts based on thresholds
- **Query Language**: PromQL for complex metric analysis
- **Data Retention**: Configurable retention periods

#### Grafana (Visualization & Dashboards)
- **Data Visualization**: Rich graphs, charts, and panels
- **Dashboard Creation**: Pre-built and custom dashboards
- **Multi-Data Source**: Can combine Prometheus with other sources
- **User Interface**: Web-based interface for operators
- **Alerting UI**: Visual alert management

#### Architecture Flow
```
PEPCTL → Prometheus → Grafana → Operators
   ↓         ↓          ↓
Metrics   Storage   Visualization
```

### Launching Monitoring Stack

#### Option 1: Docker Compose (Recommended)
```bash
# Start full monitoring stack
cd monitoring/
docker-compose up -d

# Services will be available at:
# - Prometheus: http://localhost:9091
# - Grafana: http://localhost:3000 (admin/admin)
# - PEPCTL Metrics: http://localhost:9090/metrics
```

#### Option 2: Manual Installation
```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*
./prometheus --config.file=../monitoring/prometheus.yml

# Install Grafana
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana
sudo systemctl start grafana-server
```

#### Option 3: System Services
```bash
# Install as system services
sudo cp monitoring/pepctl-prometheus.service /etc/systemd/system/
sudo cp monitoring/pepctl-grafana.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pepctl-prometheus pepctl-grafana
sudo systemctl start pepctl-prometheus pepctl-grafana
```

## Quick Start

### 1. Install Dependencies
```bash
# Run the automated dependency installer
./scripts/install_deps.sh

# Or install manually (Ubuntu/Debian)
sudo apt-get install -y \
  build-essential cmake \
  libbpf-dev libelf-dev \
  libboost-all-dev \
  nlohmann-json3-dev \
  libspdlog-dev libspdlog1.12 \
  dpkg-dev debhelper # For packaging
```

### 2. Build the Project
```bash
# Build everything (recommended)
./scripts/build.sh

# Build specific targets
./scripts/build.sh core     # Libraries only
./scripts/build.sh tests    # All tests
./scripts/build.sh main     # Main executable only
./scripts/build.sh e2e      # End-to-end tests

# Debug build with coverage
./scripts/build.sh --debug --coverage tests
```

### 3. Run Tests
```bash
# Run all tests
./scripts/test.sh

# Run specific test suites  
./scripts/test.sh unit         # Unit tests only
./scripts/test.sh integration  # Integration tests only
sudo ./scripts/test.sh e2e     # E2E tests (requires root)

# Run with coverage report
./scripts/test.sh --coverage unit
```

### 4. Install & Start Service
```bash
# Create and install Debian package (recommended)
./scripts/package-deb.sh --build
sudo dpkg -i dist/pepctl_*.deb

# Or install manually
sudo make -C build install
sudo systemctl enable pepctl
sudo systemctl start pepctl

# Check status
sudo systemctl status pepctl
journalctl -u pepctl -f
```

### 5. Verify Installation
```bash
# Check service status
curl http://localhost:8080/api/v1/status

# View metrics
curl http://localhost:9090/metrics

# Check eBPF program
sudo bpftool net show
sudo bpftool prog show
```

## Installation & Deployment

### Development Installation
```bash
# Build and install locally
./scripts/build.sh
sudo make -C build install
```

### Production Deployment (Debian/Ubuntu)
```bash
# Create and install DEB package
./scripts/package-deb.sh --build
sudo dpkg -i dist/pepctl_*.deb

# Service is automatically started
sudo systemctl status pepctl
```

### Docker Deployment
```bash
# Build Docker image
docker build -t pepctl:latest .

# Run container with privileges for eBPF
docker run --privileged --net=host \
  -v /etc/pepctl:/etc/pepctl \
  pepctl:latest
```

## Configuration

### Main Configuration (/etc/pepctl/configs/pepctl.conf)
```json
{
  "log": {
    "level": "info"
  },
  "server": {
    "admin_port": 8080,
    "metrics_port": 9090
  },
  "network": {
    "interface": "auto"
  },
  "metrics": {
    "enabled": true
  },
  "policy": {
    "capacity": 10000,
    "policies_file": "/etc/pepctl/policies/production.json"
  },
  "ebpf": {
    "program_path": "/usr/share/pepctl/ebpf/packet_filter.o"
  }
}
```

### Policy Configuration (/etc/pepctl/policies/production.json)
```json
{
  "policies": [
    {
      "id": "allow_ssh",
      "action": "ALLOW",
      "dst_port": 22,
      "protocol": "TCP",
      "description": "Allow SSH access"
    },
    {
      "id": "block_known_bad_ips",
      "action": "BLOCK", 
      "src_ip": "192.168.1.100",
      "description": "Block known malicious IP"
    }
  ]
}
```

## Usage Examples

### Basic Daemon Operations
```bash
# Check service status
sudo systemctl status pepctl

# Start/stop service
sudo systemctl start pepctl
sudo systemctl stop pepctl

# View logs
journalctl -u pepctl -f

# Run in foreground (development)
sudo /usr/bin/pepctl --config /etc/pepctl/pepctl.conf
```

### Policy Management
```bash
# List current policies
curl http://localhost:8080/api/v1/policies | jq

# Add a blocking policy
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block_attacker",
    "action": "BLOCK",
    "src_ip": "192.168.1.100",
    "description": "Block known attacker"
  }'

# Add rate limiting policy  
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "limit_api",
    "action": "RATE_LIMIT",
    "dst_port": 8080,
    "rate_limit": 1000000,
    "description": "Limit API traffic to 1MB/s"
  }'
```

### Monitoring Examples
```bash
# View real-time metrics
curl http://localhost:9090/metrics

# Check packet processing stats
curl http://localhost:8080/api/v1/stats | jq

# Monitor eBPF program status
sudo bpftool prog show
sudo bpftool map show
```

## Monitoring & Process Analysis Tools

### Universal Process Monitor

The project includes a comprehensive universal process monitoring tool that can monitor any Linux process, not just PEPCTL-specific ones.

```bash
# Monitor any process by name
./scripts/monitor_process_stats.sh nginx
./scripts/monitor_process_stats.sh firefox
./scripts/monitor_process_stats.sh "java.*tomcat"

# Monitor by PID
./scripts/monitor_process_stats.sh 1234

# List processes matching pattern
./scripts/monitor_process_stats.sh --list apache

# Monitor with custom interval (10 seconds)
./scripts/monitor_process_stats.sh firefox 10

# Interactive examples and menu
./scripts/monitor_examples.sh
```

### Monitoring Features

The universal monitor provides detailed insights into:

- **Basic Information**: Process name, state, PID, parent PID, user/group IDs, uptime
- **Memory Statistics**: Virtual memory, RSS, data segment, stack, executable size, library size, swap usage 
- **CPU Statistics**: User/system time (human-readable), children times, priority, nice value, thread count
- **I/O Statistics**: Read/write characters and bytes, system calls, cancelled writes
- **File Descriptors**: Count and details of open file descriptors
- **Network Connections**: Active network connections (using ss or netstat)
- **Environment**: Environment variable count
- **Process Limits**: Key resource limits

### Example Output

```bash
$ ./scripts/monitor_process_stats.sh $$
Process Statistics for PID: 925280
2025-06-13 21:22:19
==================================
Command: /usr/bin/bash --init-file /tmp/.mount_CursorPRWYi6/usr/share/cursor/resources/app/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh

Basic Information:
Name: bash
State: S (sleeping)
Pid: 925280
PPid: 685381
Uid: 1000 1000 1000 1000
Gid: 1000 1000 1000 1000
Uptime: 35m 56s

Memory Statistics:
Virtual Memory Size: 11.78MB
Resident Set Size: 6.00MB
Data Segment: 2.36MB
Stack Size: 136.00KB
Executable Size: 956.00KB
```

### Interactive Examples

```bash
# Run guided examples
./scripts/monitor_examples.sh --examples

# Interactive menu with multiple options
./scripts/monitor_examples.sh
```

## Build System Reference

### Available Build Targets

```bash
# Target groups
./scripts/build.sh all # Everything (default)
./scripts/build.sh core # Core libraries
./scripts/build.sh libs # Same as core
./scripts/build.sh main # Main executable
./scripts/build.sh tests # All tests
./scripts/build.sh e2e # E2E tests only
./scripts/build.sh integration # Integration tests only

# Individual targets
./scripts/build.sh pepctl_core pepctl_policy pepctl_ebpf pepctl_metrics pepctl_logger pepctl pepctl_tests pepctl_integration_test pepctl_test_client pepctl_e2e_tests

# Build options
./scripts/build.sh --debug # Debug build
./scripts/build.sh --clean # Clean build
./scripts/build.sh --verbose # Verbose output
./scripts/build.sh -j 16 # 16 parallel jobs
./scripts/build.sh --coverage # Enable coverage
```

### Test Runner Options

```bash
# Test types
./scripts/test.sh all # All tests (default)
./scripts/test.sh unit # Unit tests only
./scripts/test.sh integration # Integration tests only
./scripts/test.sh e2e # E2E tests (needs root)

# Test options
./scripts/test.sh --verbose # Verbose output
./scripts/test.sh --coverage # Generate coverage
./scripts/test.sh --valgrind # Memory checking
./scripts/test.sh --filter "Policy*" # Filter tests
./scripts/test.sh --xml # XML reports
./scripts/test.sh --json # JSON reports
```

### Package Generation

```bash
# Basic package creation
./scripts/package-deb.sh

# Package with build
./scripts/package-deb.sh --build

# Custom package version
./scripts/package-deb.sh -v 1.2.0 -r 3

# Custom maintainer
./scripts/package-deb.sh -m "Your Name <your@email.com>"

# Clean package build
./scripts/package-deb.sh --clean --build
```

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/TEST_SUITES.md`](docs/TEST_SUITES.md) | Complete testing documentation |
| [`docs/E2E_TESTING_SCENARIOS.md`](docs/E2E_TESTING_SCENARIOS.md) | E2E test scenarios |
| [`docs/E2E_IMPLEMENTATION_SUMMARY.md`](docs/E2E_IMPLEMENTATION_SUMMARY.md) | E2E implementation details |
| [`tests/e2e/README.md`](tests/e2e/README.md) | E2E setup and troubleshooting |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Configuration reference |
| [`docs/API.md`](docs/API.md) | REST API documentation |
| [`docs/PROCESS_MONITORING.md`](docs/PROCESS_MONITORING.md) | Universal process monitoring guide |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Project organization and structure |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Development guidelines |

## Performance & Benchmarks

- **Packet Processing**: >1M packets/sec on modern hardware
- **Policy Lookup**: O(1) hash table lookup with <1μs latency 
- **Memory Usage**: <50MB RSS for 10K policies
- **CPU Usage**: <5% on 4-core system under normal load
- **eBPF Overhead**: <100ns per packet processing

## System Requirements

### Minimum Requirements
- Linux kernel 4.15+ with eBPF support
- 2GB RAM, 2 CPU cores
- 100MB disk space

### Recommended Requirements 
- Linux kernel 5.4+ with BTF support
- 4GB RAM, 4+ CPU cores
- 1GB disk space for logs and packages

### Supported Distributions
- Ubuntu 20.04 LTS+
- Debian 11+
- RHEL/CentOS 8+
- Fedora 35+

## Troubleshooting

### Common Issues

1. **eBPF Program Load Failure**
```bash
# Check kernel eBPF support
zgrep CONFIG_BPF_SYSCALL /proc/config.gz

# Verify BTF availability
ls /sys/kernel/btf/vmlinux
```

2. **Permission Denied**
```bash
# Add required capabilities
sudo setcap cap_bpf,cap_net_admin+ep ./build/pepctl

# Or run as root
sudo ./build/pepctl
```

3. **E2E Tests Failing**
```bash
# Check network namespace support
sudo ip netns add test-ns
sudo ip netns delete test-ns

# Run E2E tests with debug
sudo ./scripts/test.sh --verbose e2e
```

### Getting Help

- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Join GitHub Discussions 
- **Documentation**: Check `docs/` directory
- **Logs**: Check `/var/log/pepctl/` or `journalctl -u pepctl`

## Contributing

We welcome contributions! Please see [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for:

- Development setup
- Coding standards 
- Testing requirements
- Pull request process
- Code review guidelines

### Development Workflow

```bash
# 1. Setup development environment
./scripts/install_deps.sh
./scripts/build.sh --debug tests

# 2. Make changes and test
./scripts/test.sh --coverage
./scripts/build.sh --clean

# 3. Create package for testing
./scripts/package-deb.sh --build

# 4. Submit pull request
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- eBPF community for kernel integration
- Boost libraries for networking and containers
- Google Test framework for comprehensive testing
- spdlog for high-performance logging
- Linux kernel developers for eBPF infrastructure 