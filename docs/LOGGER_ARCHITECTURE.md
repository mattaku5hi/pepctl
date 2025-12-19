# PEPCTL Logger Architecture & Features

## Overview

The PEPCTL logger is a sophisticated, high-performance logging system built on top of the `spdlog` library. It provides structured logging, multiple output sinks, performance monitoring, and comprehensive categorization for network policy enforcement operations.

## Key Features

### 🎯 **Structured Logging**
- **JSON Format Support**: Native JSON output for log aggregation systems
- **Contextual Information**: Rich metadata attached to each log entry
- **Category-based Organization**: Logical grouping of log messages
- **Field Extensibility**: Custom key-value pairs for specific use cases

### 🚀 **High Performance**
- **Asynchronous Logging**: Non-blocking log operations using spdlog's async capabilities
- **Memory Efficient**: Optimized data structures and minimal allocations
- **Thread-Safe**: Concurrent logging from multiple threads
- **Statistics Tracking**: Built-in performance metrics

### 📊 **Multiple Output Sinks**
- **Console Output**: Colored terminal output for development
- **File Logging**: Rotating file logs with size management
- **Systemd Journal**: Native Linux systemd integration
- **Syslog**: Traditional Unix syslog support

### 🔧 **Runtime Configuration**
- **Dynamic Log Levels**: Change verbosity without restart
- **Pattern Customization**: Flexible log format configuration
- **Sink Management**: Enable/disable outputs dynamically

## Architecture Components

### Core Classes

#### `Logger` Class
The main logging interface providing:
- **Initialization & Configuration**: Setup with `LoggerConfig`
- **Level-based Logging**: TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
- **Context-aware Logging**: Rich metadata support
- **Statistics Collection**: Performance and usage metrics
- **Lifecycle Management**: Proper initialization and shutdown

#### `LogContext` Structure
Provides structured context for log entries:
```cpp
struct LogContext {
    LogCategory category;           // Message category
    std::string component;          // Component name
    std::string session_id;         // Session identifier
    std::string client_ip;          // Client IP address
    std::string policy_id;          // Policy identifier
    std::unordered_map<std::string, std::string> extra_fields; // Custom fields
};
```

**Fluent Interface Pattern**:
```cpp
LogContext ctx(LogCategory::POLICY);
ctx.withComponent("PolicyEngine")
   .withClientIp("192.168.1.100")
   .withPolicy("block-malicious")
   .withField("action", "BLOCK")
   .withField("reason", "malicious_ip");
```

#### `LoggerConfig` Structure
Comprehensive configuration options:
```cpp
struct LoggerConfig {
    LogLevel level = LogLevel::INFO;                    // Minimum log level
    std::string logFilePath;                           // File output path
    std::string pattern;                               // Log format pattern
    bool consoleOutput = true;                         // Console sink
    bool fileOutput = false;                           // File sink
    bool syslogOutput = false;                         // Syslog sink
    bool systemdOutput = true;                         // Systemd journal sink
    size_t maxFileSize = 10 * 1024 * 1024;           // File rotation size
    size_t maxFiles = 5;                              // Number of rotated files
    bool structuredLogging = true;                     // Enable structured output
    std::string logFormat = "json";                    // "json" or "text"
};
```

### Log Levels

```cpp
enum class LogLevel {
    TRACE = 0,      // Detailed execution flow
    DBG = 1,        // Debug information (renamed from DEBUG to avoid macro conflicts)
    INFO = 2,       // General information
    WARN = 3,       // Warning conditions
    ERROR = 4,      // Error conditions
    CRITICAL = 5,   // Critical failures
    OFF = 6         // Disable logging
};
```

### Log Categories

```cpp
enum class LogCategory {
    SYSTEM,         // System-level events (startup, shutdown, configuration)
    POLICY,         // Policy enforcement events
    EBPF,          // eBPF program operations
    NETWORK,       // Network packet processing
    METRICS,       // Performance and monitoring data
    SECURITY,      // Security-related events
    PERFORMANCE    // Performance measurements
};
```

## Usage Patterns

### Basic Logging

```cpp
// Simple message logging
gLogger->info("PEPCTL daemon started");
gLogger->error("Failed to load configuration");

// With context
LogContext ctx(LogCategory::SYSTEM);
ctx.withComponent("ConfigLoader");
gLogger->info(ctx, "Configuration loaded successfully");
```

### Structured Logging

```cpp
// Policy enforcement logging
LogContext policyCtx(LogCategory::POLICY);
policyCtx.withPolicy("web-access-control")
         .withClientIp("10.0.1.50")
         .withField("action", "ALLOW")
         .withField("port", "443")
         .withField("protocol", "TCP");
gLogger->info(policyCtx, "Policy applied successfully");
```

### Specialized Event Logging

```cpp
// Policy events
gLogger->logPolicyEvent("firewall-001", "BLOCK", "192.168.1.100", 
                       "Blocked malicious traffic");

// Security events
gLogger->logSecurityEvent("intrusion_attempt", "10.0.1.25", 
                         "Multiple failed authentication attempts", 
                         LogLevel::WARN);

// Performance events
std::unordered_map<std::string, std::string> metrics = {
    {"packets_processed", "1500"},
    {"cpu_usage", "15.2%"},
    {"memory_usage", "45MB"}
};
gLogger->logPerformanceEvent("packet_processing", 125.5, metrics);

// Network events
PacketInfo packet = {/* packet details */};
gLogger->logNetworkEvent("eth0", "packet_received", packet);

// eBPF events
gLogger->logEbpfEvent("program_load", true, "Successfully loaded BPF program");
```

### Template-based Formatted Logging

```cpp
LogContext ctx(LogCategory::NETWORK);
gLogger->info(ctx, "Processed {} packets in {:.2f}ms", packetCount, duration);
gLogger->error(ctx, "Connection failed: {} (error code: {})", errorMsg, errorCode);
```

## Output Formats

### JSON Structured Output
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "message": "Policy applied successfully",
  "category": "POLICY",
  "component": "PolicyEngine",
  "client_ip": "10.0.1.50",
  "policy_id": "web-access-control",
  "fields": {
    "action": "ALLOW",
    "port": "443",
    "protocol": "TCP"
  }
}
```

### Text Structured Output
```
2024-01-15 10:30:45 category=POLICY component=PolicyEngine client_ip=10.0.1.50 policy_id=web-access-control action=ALLOW port=443 protocol=TCP message="Policy applied successfully"
```

### Console Output (with colors)
```
[2024-01-15 10:30:45.123] [info] [pepctl] [POLICY][PolicyEngine][10.0.1.50] Policy applied successfully
```

## Performance Features

### Statistics Tracking

```cpp
struct LogStats {
    uint64_t total_messages;                    // Total messages logged
    uint64_t messages_by_level[7];             // Count per log level
    uint64_t messages_by_category[7];          // Count per category
    std::chrono::system_clock::time_point last_message_time;
};

// Usage
auto stats = gLogger->getStats();
std::cout << "Total messages: " << stats.total_messages << std::endl;
std::cout << "Error messages: " << stats.messages_by_level[static_cast<int>(LogLevel::ERROR)] << std::endl;
```

### Memory Management
- **Rotating Files**: Automatic log rotation based on size
- **Buffer Management**: Efficient memory usage with spdlog's buffer pools
- **String Optimization**: Minimal string copying and allocation

### Thread Safety
- **Concurrent Access**: Multiple threads can log simultaneously
- **Lock-free Operations**: High-performance concurrent data structures
- **Statistics Protection**: Thread-safe statistics updates

## Configuration Examples

### Development Configuration
```cpp
LoggerConfig devConfig;
devConfig.level = LogLevel::DBG;
devConfig.consoleOutput = true;
devConfig.fileOutput = false;
devConfig.structuredLogging = false;
devConfig.pattern = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";
```

### Production Configuration
```cpp
LoggerConfig prodConfig;
prodConfig.level = LogLevel::INFO;
prodConfig.consoleOutput = false;
prodConfig.fileOutput = true;
prodConfig.systemdOutput = true;
prodConfig.logFilePath = "/var/log/pepctl/pepctl.log";
prodConfig.maxFileSize = 50 * 1024 * 1024;  // 50MB
prodConfig.maxFiles = 10;
prodConfig.structuredLogging = true;
prodConfig.logFormat = "json";
```

### High-Performance Configuration
```cpp
LoggerConfig perfConfig;
perfConfig.level = LogLevel::WARN;  // Reduce verbosity
perfConfig.consoleOutput = false;   // Disable slow console output
perfConfig.fileOutput = true;
perfConfig.structuredLogging = true;
// Use async logging (configured in spdlog setup)
```

## Integration with PEPCTL Components

### Policy Engine Integration
```cpp
class PolicyEngine {
    void evaluatePolicy(const PacketInfo& packet) {
        LogContext ctx(LogCategory::POLICY);
        ctx.withClientIp(packet.src.toString())
           .withField("protocol", std::to_string(packet.protocol))
           .withField("port", std::to_string(packet.dst.port));
        
        auto result = applyPolicies(packet);
        
        gLogger->info(ctx, "Policy evaluation: {} for {}:{}", 
                     result.action, packet.src.toString(), packet.dst.port);
    }
};
```

### eBPF Program Integration
```cpp
class EbpfManager {
    bool loadProgram(const std::string& programPath) {
        LogContext ctx(LogCategory::EBPF);
        ctx.withComponent("EbpfManager")
           .withField("program_path", programPath);
        
        if (/* load success */) {
            gLogger->logEbpfEvent("program_load", true, 
                                 "Loaded program: " + programPath);
            return true;
        } else {
            gLogger->logEbpfEvent("program_load", false, 
                                 "Failed to load: " + programPath);
            return false;
        }
    }
};
```

### Network Interface Integration
```cpp
class NetworkInterface {
    void processPacket(const PacketInfo& packet) {
        LogContext ctx(LogCategory::NETWORK);
        ctx.withField("interface", interfaceName)
           .withField("packet_size", std::to_string(packet.size));
        
        gLogger->logNetworkEvent(interfaceName, "packet_processed", packet);
    }
};
```

## Best Practices

### 1. **Use Appropriate Log Levels**
- `TRACE`: Detailed execution flow, function entry/exit
- `DEBUG`: Variable values, state changes, debugging info
- `INFO`: Normal operation events, successful operations
- `WARN`: Recoverable errors, deprecated usage
- `ERROR`: Error conditions that don't stop execution
- `CRITICAL`: Fatal errors that may cause shutdown

### 2. **Leverage Structured Logging**
```cpp
// Good: Structured with context
LogContext ctx(LogCategory::SECURITY);
ctx.withClientIp(clientIp).withField("attempt_count", "5");
gLogger->warn(ctx, "Multiple failed login attempts detected");

// Avoid: Unstructured string concatenation
gLogger->warn("Client " + clientIp + " failed login 5 times");
```

### 3. **Use Categories Consistently**
- `SYSTEM`: Daemon lifecycle, configuration changes
- `POLICY`: Policy evaluation, rule application
- `SECURITY`: Authentication, authorization, threats
- `NETWORK`: Packet processing, interface events
- `PERFORMANCE`: Timing, resource usage, bottlenecks

### 4. **Performance Considerations**
```cpp
// Check log level before expensive operations
if (gLogger->getLevel() <= LogLevel::DBG) {
    std::string expensiveDebugInfo = generateDetailedReport();
    gLogger->debug(ctx, expensiveDebugInfo);
}

// Use template formatting for better performance
gLogger->info(ctx, "Processed {} packets in {}ms", count, duration);
```

### 5. **Error Handling**
```cpp
try {
    riskyOperation();
} catch (const std::exception& e) {
    LogContext ctx(LogCategory::SYSTEM);
    ctx.withComponent("RiskyComponent")
       .withField("error_type", typeid(e).name());
    gLogger->error(ctx, "Operation failed: {}", e.what());
}
```

## Troubleshooting

### Common Issues

1. **Logger Not Initialized**
   - Ensure `gLogger->initialize(config)` is called before logging
   - Check return value for initialization success

2. **Missing Log Output**
   - Verify log level configuration
   - Check sink configuration (console, file, systemd)
   - Ensure proper permissions for log file paths

3. **Performance Issues**
   - Use appropriate log levels in production
   - Consider async logging for high-throughput scenarios
   - Monitor log file sizes and rotation

4. **JSON Parsing Errors**
   - Validate JSON structure in log aggregation systems
   - Handle special characters in log messages
   - Use proper escaping for field values

### Debug Configuration
```cpp
LoggerConfig debugConfig;
debugConfig.level = LogLevel::TRACE;
debugConfig.consoleOutput = true;
debugConfig.pattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] [%s:%#] %v";
// %s:%# adds source file and line number
```

## Future Enhancements

### Planned Features
- **Remote Logging**: Network-based log shipping
- **Log Compression**: Automatic compression of rotated files
- **Metrics Integration**: Prometheus metrics export
- **Configuration Hot-reload**: Runtime configuration updates
- **Custom Sinks**: Plugin architecture for custom outputs

### Performance Optimizations
- **Lock-free Logging**: Further reduce contention
- **Memory Pools**: Reduce allocation overhead
- **Batch Processing**: Group log writes for efficiency
- **Filtering**: Pre-filter logs before formatting

This logger provides a robust foundation for monitoring and debugging the PEPCTL daemon while maintaining high performance and flexibility for various deployment scenarios. 