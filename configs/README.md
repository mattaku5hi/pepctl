# PEPCTL Configuration Files

This directory contains all PEPCTL configuration files organized by environment.

## Available Configurations

### `production.json`
- **Purpose**: Production deployment
- **Log Level**: `info`
- **Log File**: `/var/log/pepctl.log`
- **Interface**: `enx00e099002775`
- **Policies**: `policies/production.json`
- **Features**: Optimized for performance and stability

### `development.json`
- **Purpose**: Development and debugging
- **Log Level**: `debug`
- **Log File**: `/tmp/pepctl.log`
- **Interface**: `enx00e099002775`
- **Policies**: `policies/development.json`
- **Features**: Enhanced logging for development

### `testing.json`
- **Purpose**: Testing all packet categories
- **Log Level**: `debug`
- **Log File**: `/tmp/pepctl.log`
- **Interface**: `enx00e099002775` (TC mode)
- **Policies**: `policies/testing.json`
- **Features**: Designed to demonstrate ALLOW, BLOCK, LOG_ONLY, RATE_LIMIT

### `loopback.json`
- **Purpose**: Local testing on loopback interface
- **Log Level**: `debug`
- **Log File**: `/tmp/pepctl.log`
- **Interface**: `lo`
- **Policies**: `policies/loopback.json`
- **Features**: Safe testing without affecting network traffic

## Usage

Use the startup script to launch with any configuration:

```bash
# Start in development mode (default)
./scripts/start_pepctl.sh development

# Start in production mode
./scripts/start_pepctl.sh production

# Start in testing mode
./scripts/start_pepctl.sh testing

# Start on loopback interface
./scripts/start_pepctl.sh loopback
```

## Configuration Structure

All configurations follow this structure:

```json
{
"daemon": { "mode": true },
"log": { "level": "info|debug", "file": "/path/to/log" },
"server": { "admin_port": 8080, "metrics_port": 9090 },
"network": { "interface": "interface_name", "mode": "xdp|tc" },
"metrics": { "enabled": true },
"policy": { "capacity": 1000, "policies_file": "/path/to/policies.json" },
"ebpf": { "program_path": "/path/to/packet_filter.o" }
}
``` 