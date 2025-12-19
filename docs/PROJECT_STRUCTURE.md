# 📁 PEPCTL Project Structure

This document describes the organized structure of the PEPCTL project, including all directories, files, and their purposes.

## 🏗️ Directory Overview

```
pepctl/
├── 📁 build-ninja/              # Debug build artifacts (Clang + Ninja)
├── 📁 build-ninja-release/      # Release build artifacts (Clang + Ninja)
├── 📁 docs/                     # Documentation files
├── 📁 ebpf/                     # eBPF programs and related code
├── 📁 monitoring/               # Monitoring and observability
├── 📁 policies/                 # Policy configuration files
├── 📁 scripts/                  # Utility and automation scripts
├── 📁 src/                      # Source code
├── 📁 systemd/                  # Systemd service files
├── 📁 tests/                    # Test suites
└── 📄 Configuration files       # Project configuration
```

## 📚 Documentation (`docs/`)

| **File** | **Purpose** | **Description** |
|----------|-------------|-----------------|
| `PROCESS_MONITORING.md` | Process monitoring guide | Linux process monitoring fundamentals |
| `PROJECT_STRUCTURE.md` | Project organization | This file - project structure documentation |
| `PROMETHEUS_QUERIES.md` | Metrics queries | Prometheus query examples and guides |
| `METRICS_SERVER_ARCHITECTURE.md` | Metrics architecture | Detailed metrics server documentation |
| `POLICY_ENGINE_DETAILED.md` | Policy engine | Comprehensive policy engine documentation |

## 🔧 Scripts (`scripts/`)

### **Monitoring & Statistics**
| **Script** | **Purpose** | **Usage** |
|------------|-------------|-----------|
| `monitor_process_stats.sh` | Process monitoring | `./scripts/monitor_process_stats.sh pepctl` |
| `reset_statistics_guide.sh` | Statistics reset | `./scripts/reset_statistics_guide.sh` |

### **Testing & Traffic Generation**
| **Script** | **Purpose** | **Usage** |
|------------|-------------|-----------|
| `test_traffic_generator.sh` | Traffic generation | `./scripts/test_traffic_generator.sh burst` |
| `test_policy_enforcement.sh` | Policy testing | `./scripts/test_policy_enforcement.sh demo` |

## 📊 Monitoring (`monitoring/`)

### **Structure**
```
monitoring/
├── 📁 prometheus/               # Prometheus configuration
│   └── prometheus.yml          # Prometheus config file
├── 📁 grafana/                 # Grafana configuration
│   ├── provisioning/           # Grafana provisioning
│   │   ├── dashboards/         # Dashboard definitions
│   │   └── datasources/        # Data source configurations
│   └── dashboards/             # Dashboard JSON files
├── docker-compose.monitoring.yml # Docker compose for monitoring stack
└── setup-monitoring.sh         # Monitoring setup script
```

### **Components**
| **Component** | **Port** | **Purpose** |
|---------------|----------|-------------|
| **Prometheus** | 9091 | Metrics collection and storage |
| **Grafana** | 3000 | Metrics visualization and dashboards |
| **PEPCTL Metrics** | 9090 | Application metrics endpoint |

## 🛡️ Policies (`policies/`)

| **File** | **Purpose** | **Description** |
|----------|-------------|-----------------|
| `test_policy_presets.json` | Test policies | Pre-defined policies for testing |
| `production_policies.json` | Production policies | Production-ready policy configurations |

## 🧪 Testing (`tests/`)

### **Structure**
```
tests/
├── 📁 unit/                    # Unit tests
├── 📁 integration/             # Integration tests
├── 📁 e2e/                     # End-to-end tests
└── 📁 performance/             # Performance tests
```

### **Test Categories**
| **Category** | **Purpose** | **Examples** |
|--------------|-------------|--------------|
| **Unit** | Component testing | Policy engine, metrics server |
| **Integration** | System integration | API endpoints, eBPF integration |
| **E2E** | Full system testing | Network traffic processing |
| **Performance** | Load and stress testing | High traffic scenarios |

## 💻 Source Code (`src/`)

### **Core Components**
| **File** | **Purpose** | **Description** |
|----------|-------------|-----------------|
| `core.cpp` | Main daemon | Core PEPCTL daemon implementation |
| `policy_engine.cpp` | Policy management | Policy loading, matching, enforcement |
| `ebpf_manager.cpp` | eBPF integration | eBPF program management |
| `metrics_server.cpp` | Metrics & API | HTTP server for metrics and management |
| `logger.cpp` | Logging system | Structured logging implementation |

### Public Headers (in-tree)
Project headers live under `src/pepctl/` and are included as `#include "pepctl/<name>.h"`.

## 🔌 eBPF (`ebpf/`)

| **File** | **Purpose** | **Description** |
|----------|-------------|-----------------|
| `packet_filter.c` | Packet filtering | eBPF program for packet interception |
| `packet_filter.h` | eBPF headers | Shared structures and definitions |

## 🏗️ Build System (`build/`)

### **Generated Structure**
```
build-ninja/
├── 📁 src/                     # Compiled binaries
│   └── pepctl                  # Main executable
├── 📁 tests/                   # Test executables
├── 📁 CMakeFiles/              # CMake build files
└── 📄 build.ninja              # Ninja build file
```

## ⚙️ Configuration Files

### **Root Level**
| **File** | **Purpose** | **Description** |
|----------|-------------|-----------------|
| `CMakeLists.txt` | Build configuration | CMake build system configuration |
| `test_config.json` | Test configuration | Configuration for testing |
| `.clang-format` | Code formatting | C++ code formatting rules |
| `.clang-tidy` | Static analysis | C++ static analysis configuration |

### **Test Configurations**
| **File** | **Purpose** | **Description** |
|----------|-------------|-----------------|
| `test_comprehensive_policies.json` | Test policies | Comprehensive policy set for testing |
| `test_policies_demo.json` | Demo policies | Simple policies for demonstrations |

## 🚀 Quick Start Guide

### **1. Build the Project**
```bash
cmake --preset clang-ninja-debug
cmake --build --preset build-debug
```

### **2. Start Monitoring Stack**
```bash
cd monitoring
sudo docker-compose -f docker-compose.monitoring.yml up -d
```

### **3. Run PEPCTL Daemon**
```bash
sudo ./build-ninja/src/pepctl --config ./configs/development.json --daemon
```

### **4. Monitor Process**
```bash
./scripts/monitor_process_stats.sh pepctl
```

### **5. Access Dashboards**
- **Grafana**: http://localhost:3000 (admin/pepctl123)
- **Prometheus**: http://localhost:9091
- **PEPCTL Metrics**: http://localhost:9090/metrics

## 📋 File Organization Principles

### **1. Separation of Concerns**
- **Source code** in `src/`
- **Documentation** in `docs/`
- **Scripts** in `scripts/`
- **Monitoring** in `monitoring/`

### **2. Logical Grouping**
- Related files grouped together
- Clear naming conventions
- Consistent directory structure

### **3. Environment Separation**
- Test configurations separate from production
- Development tools in dedicated directories
- Build artifacts isolated in `build/`

### **4. Accessibility**
- Important files at appropriate levels
- Clear file naming
- Comprehensive documentation

## 🔗 Related Documentation

- [Process Monitoring Guide](PROCESS_MONITORING.md)
- [Prometheus Queries](PROMETHEUS_QUERIES.md)
- [Metrics Server Architecture](METRICS_SERVER_ARCHITECTURE.md)
- [Policy Engine Details](POLICY_ENGINE_DETAILED.md)

## 📝 Maintenance

### **Regular Tasks**
- Update documentation when adding new files
- Maintain consistent naming conventions
- Review and organize test files
- Keep monitoring configurations updated

### **Best Practices**
- Document new directories and files
- Follow established naming patterns
- Group related functionality together
- Maintain clear separation between components 