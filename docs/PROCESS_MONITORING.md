# Linux Process Monitoring Guide

This guide covers comprehensive Linux process monitoring using the `/proc` filesystem and our universal monitoring script.

## Universal Process Monitor Script

The `scripts/monitor_process_stats.sh` script provides detailed monitoring for any Linux process.

### Usage

```bash
# Monitor by process name
./scripts/monitor_process_stats.sh nginx

# Monitor by PID
./scripts/monitor_process_stats.sh 1234

# Monitor with custom interval (10 seconds)
./scripts/monitor_process_stats.sh firefox 10

# List all processes matching a pattern
./scripts/monitor_process_stats.sh --list apache

# Monitor Java applications
./scripts/monitor_process_stats.sh "java.*tomcat"

# Show help
./scripts/monitor_process_stats.sh --help
```

### Features

The script provides comprehensive monitoring including:

- **Basic Information**: Process name, state, PID, parent PID, user/group IDs, uptime
- **Memory Statistics**: Virtual memory, RSS, data segment, stack, executable size, library size, swap usage
- **CPU Statistics**: User/system time (formatted), children times, priority, nice value, thread count
- **I/O Statistics**: Read/write characters and bytes, system calls, cancelled writes
- **File Descriptors**: Count and details of open file descriptors
- **Network Connections**: Active network connections (using ss or netstat)
- **Environment**: Environment variable count
- **Process Limits**: Key resource limits

### Examples

#### Monitor Current Shell
```bash
./scripts/monitor_process_stats.sh $$
```

#### Monitor System Processes
```bash
# Monitor systemd (requires appropriate permissions)
sudo ./scripts/monitor_process_stats.sh 1

# Monitor user systemd
./scripts/monitor_process_stats.sh --list "systemd --user"
./scripts/monitor_process_stats.sh 2924  # Use specific PID from list
```

#### Monitor Applications
```bash
# Web browsers
./scripts/monitor_process_stats.sh firefox
./scripts/monitor_process_stats.sh chrome

# Development tools
./scripts/monitor_process_stats.sh "code.*cursor"
./scripts/monitor_process_stats.sh "java.*idea"

# System services
./scripts/monitor_process_stats.sh sshd
./scripts/monitor_process_stats.sh nginx
```

## Understanding /proc Filesystem

### **1. /proc Filesystem**

The `/proc` filesystem provides real-time process information:

```bash
# Process-specific directories
/proc/PID/stat      # Process statistics
/proc/PID/status    # Human-readable status
/proc/PID/io        # I/O statistics
/proc/PID/fd/       # File descriptors
/proc/PID/cmdline   # Command line arguments
/proc/PID/environ   # Environment variables
```

### **2. Key Files Explained**

#### **/proc/PID/stat**
Contains process statistics in a single line:
```
pid comm state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime vsize rss rsslim...
```

#### **/proc/PID/status**
Human-readable process status:
```
Name:   pepctl
State:  S (sleeping)
Tgid:   1234
Pid:    1234
PPid:   1
VmSize: 123456 kB
VmRSS:  12345 kB
```

#### **/proc/PID/io**
I/O statistics:
```
rchar: 1234567
wchar: 123456
syscr: 1234
syscw: 123
read_bytes: 123456
write_bytes: 12345
```

### **3. Memory Types Explained**

| **Memory Type** | **Description** | **Use Case** |
|-----------------|-----------------|--------------|
| **VmSize** | Total virtual memory | Overall memory footprint |
| **VmRSS** | Physical memory in use | Actual RAM usage |
| **VmData** | Data/heap segment | Dynamic allocations |
| **VmStk** | Stack memory | Function calls, local variables |
| **VmExe** | Executable code | Program instructions |

### **4. CPU Time Metrics**

| **Metric** | **Description** | **Units** |
|------------|-----------------|-----------|
| **utime** | User mode CPU time | Jiffies (1/100 sec) |
| **stime** | Kernel mode CPU time | Jiffies |
| **cutime** | Children user time | Jiffies |
| **cstime** | Children system time | Jiffies |

## 🎯 PEPCTL-Specific Monitoring

### **1. Application Metrics**

PEPCTL provides additional metrics via HTTP API:

```bash
# Health check
curl http://127.0.0.1:9090/health

# Detailed statistics
curl http://127.0.0.1:9090/stats

# Prometheus metrics
curl http://127.0.0.1:9090/metrics
```

### **2. Key PEPCTL Metrics**

| **Metric** | **Description** | **Endpoint** |
|------------|-----------------|--------------|
| **Packets Processed** | Total packets handled | `/stats` |
| **Packets Allowed** | Packets permitted | `/stats` |
| **Packets Blocked** | Packets denied | `/stats` |
| **Active Policies** | Number of loaded policies | `/stats` |
| **Uptime** | Service uptime in seconds | `/stats` |

### **3. Performance Indicators**

#### **Memory Usage**
- **Normal**: 10-50MB RSS for typical workloads
- **High**: >100MB may indicate memory leaks
- **Critical**: >500MB requires investigation

#### **CPU Usage**
- **Normal**: <5% CPU for moderate traffic
- **High**: >20% CPU may indicate performance issues
- **Critical**: >50% CPU requires optimization

#### **File Descriptors**
- **Normal**: 10-50 open FDs
- **High**: >100 FDs may indicate resource leaks
- **Critical**: >1000 FDs approaching system limits

## 🚨 Troubleshooting

### **1. High Memory Usage**

```bash
# Check memory details
cat /proc/PID/status | grep Vm

# Check for memory leaks
valgrind --leak-check=full ./pepctl

# Monitor memory over time
watch -n 1 'cat /proc/PID/status | grep VmRSS'
```

### **2. High CPU Usage**

```bash
# Check CPU details
cat /proc/PID/stat | awk '{print "User:", $14, "System:", $15}'

# Profile with perf
perf record -p PID
perf report

# Check thread activity
cat /proc/PID/task/*/stat
```

### **3. I/O Issues**

```bash
# Monitor I/O
watch -n 1 'cat /proc/PID/io'

# Check open files
lsof -p PID

# Monitor disk I/O
iotop -p PID
```

### **4. Network Issues**

```bash
# Check connections
netstat -tulpn | grep PID

# Monitor network I/O
nethogs -p PID

# Check socket details
ss -tulpn | grep PID
```

## 📋 Best Practices

### **1. Regular Monitoring**
- Monitor key metrics every 5-10 seconds
- Set up alerts for abnormal values
- Log metrics for historical analysis

### **2. Resource Limits**
- Set appropriate memory limits
- Monitor file descriptor usage
- Implement graceful degradation

### **3. Performance Optimization**
- Profile regularly under load
- Optimize hot code paths
- Monitor for resource leaks

### **4. Security Considerations**
- Monitor for unusual process behavior
- Check for unauthorized network connections
- Validate process integrity

## 🔗 Related Tools

### **System Monitoring**
- `htop` - Interactive process viewer
- `iotop` - I/O monitoring
- `nethogs` - Network monitoring per process

### **Profiling Tools**
- `perf` - Performance profiling
- `valgrind` - Memory debugging
- `strace` - System call tracing

### **PEPCTL Tools**
- `./scripts/monitor_process_stats.sh` - Process monitoring
- `./reset_statistics_guide.sh` - Statistics reset
- `./prometheus_queries_guide.md` - Metrics queries 