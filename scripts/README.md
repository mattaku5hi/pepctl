# PEPCTL Scripts Directory

This directory contains essential scripts for managing and testing the PEPCTL eBPF packet filtering system.

## Core Management Scripts

### `start_pepctl.sh`
**Usage:** `./scripts/start_pepctl.sh [environment]`

Starts the PEPCTL daemon with the specified environment configuration.

**Environments:**
- `production` - Uses production.json config
- `development` - Uses development.json config (default)
- `testing` - Uses testing.json config (cleans old eBPF maps)
- `loopback` - Uses loopback.json config

**Examples:**
```bash
./scripts/start_pepctl.sh production
./scripts/start_pepctl.sh development
./scripts/start_pepctl.sh testing
```

### `stop_pepctl.sh`
**Usage:** `./scripts/stop_pepctl.sh [clean]`

Stops the PEPCTL daemon and optionally cleans up eBPF resources.

**Examples:**
```bash
./scripts/stop_pepctl.sh # Stop daemon only
./scripts/stop_pepctl.sh clean # Stop daemon and clean eBPF resources
```

## Testing Scripts

### `generate_real_traffic.sh`
**Usage:** `./scripts/generate_real_traffic.sh [interface] [ip_address]`

Generates test traffic for all PEPCTL policy categories (ALLOW, BLOCK, LOG_ONLY, RATE_LIMIT).

**Examples:**
```bash
./scripts/generate_real_traffic.sh enx00e099002775 192.168.3.66
./scripts/generate_real_traffic.sh lo 127.0.0.1
./scripts/generate_real_traffic.sh eth0 10.0.0.100
```

### `manage_policies.sh`
**Usage:** `./scripts/manage_policies.sh [command]`

Comprehensive policy management and statistics tool.

**Commands:**
- `list` - Show all policies and their hit counts
- `stats` - Show detailed statistics
- `reset` - Reset policy hit counts
- `help` - Show help information

## Development Scripts

### `build.sh`
Builds the PEPCTL project with CMake.

### `install_deps.sh`
Installs all required dependencies for building PEPCTL.

### `format-code.sh`
Formats the codebase using clang-format.

### `package-deb.sh`
**Usage:** `./scripts/package-deb.sh [OPTIONS]`

Professional Debian package generator using the `packaging/debian/` structure.

**Key Features:**
- Uses professional Debian packaging with dpkg-buildpackage
- Integrates with version management system
- Supports both binary and source packages
- Automatic dependency checking
- Clean build artifact management

**Options:**
- `-v, --version VERSION` - Update version before building
- `-r, --revision REV` - Set Debian revision (default: 1)
- `--build` - Build project before packaging
- `--clean` - Clean build artifacts before packaging
- `--source` - Build source package instead of binary
- `--unsigned` - Build unsigned package (for testing)
- `--check-version` - Check version consistency
- `--show-info` - Show package information

**Examples:**
```bash
./scripts/package-deb.sh --build              # Build and package
./scripts/package-deb.sh -v 1.1.0             # Update version and package
./scripts/package-deb.sh --clean --build      # Clean, build, and package
./scripts/package-deb.sh --source             # Build source package
./scripts/package-deb.sh --show-info          # Show package info
```

### `update-version.sh`
**Usage:** `./scripts/update-version.sh [command] [version] [revision]`

Centralized version management across CMake, VERSION file, and Debian changelog.

**Commands:**
- `update VERSION [REVISION]` - Update to new version
- `check` - Check version consistency
- `show` - Show current versions

### `help.sh`
Shows comprehensive help information for the PEPCTL system.

## Code Maintenance Scripts

### `explicit-bool-fix.sh`
Fixes explicit boolean conversion issues in the codebase.

### `convert-to-camelcase.sh`
Converts code to camelCase naming convention.

---

## Quick Start

1. **Install dependencies:**
```bash
./scripts/install_deps.sh
```

2. **Build the project:**
```bash
./scripts/build.sh
```

3. **Start PEPCTL:**
```bash
./scripts/start_pepctl.sh development
```

4. **Generate test traffic:**
```bash
./scripts/generate_real_traffic.sh
```

5. **Check statistics:**
```bash
./scripts/manage_policies.sh stats
```

6. **Create Debian package:**
```bash
./scripts/package-deb.sh --build
```

7. **Stop PEPCTL:**
```bash
./scripts/stop_pepctl.sh clean
``` 