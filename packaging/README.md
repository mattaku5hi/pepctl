# PEPCTL Debian Package

This directory contains all the necessary files for creating professional Debian packages for PEPCTL.

## Package Features

### Installation Behavior
- **Pre-installation**: Stops existing service, cleans eBPF resources
- **Post-installation**: Creates user/group, sets up directories, configures systemd
- **Configuration**: Copies production.json to `/etc/pepctl/pepctl.conf`
- **Policies**: Installs policies to `/etc/pepctl/policies/`
- **Logging**: Configures systemd-journald only (no external log files)
- **eBPF**: Ensures BTF support and BPF filesystem mounting

### Directory Structure After Installation
```
/etc/pepctl/
├── pepctl.conf                    # Main configuration (from production.json)
└── policies/
    └── production.json             # Active policies

/usr/share/pepctl/
├── production.json                 # Config template
├── development.json                # Development config
├── testing.json                    # Testing config
├── policies/                       # Policy examples
│   ├── production.json
│   ├── development.json
│   └── testing.json
└── ebpf/
    └── packet_filter.o             # eBPF programs

/run/pepctl/                        # Runtime directory (pepctl user)

/lib/systemd/system/
└── pepctl.service                  # Systemd service

/etc/default/
└── pepctl                          # Environment variables

/etc/systemd/journald.conf.d/
└── pepctl.conf                     # Journal configuration
```

## Building the Package

### Method 1: Using dpkg-buildpackage (Recommended)
```bash
# Install build dependencies
sudo apt-get install debhelper-compat cmake build-essential pkg-config \
    libbpf-dev libelf-dev libboost-all-dev nlohmann-json3-dev \
    libspdlog-dev libfmt-dev libsystemd-dev linux-headers-generic

# Build the package
dpkg-buildpackage -us -uc -b

# Or use the CMake target
make deb-package
```

### Method 2: Using CMake/CPack
```bash
# Configure and build
mkdir build && cd build
cmake .. -DENABLE_TESTS=OFF
make package
```

## Package Scripts

### preinst (Pre-installation)
- Stops pepctl service if running
- Disables service temporarily
- Cleans up existing eBPF programs and maps
- Removes XDP/TC programs from all interfaces
- Removes pinned BPF maps

### postinst (Post-installation)
- Creates pepctl user and group
- Creates directory structure
- Installs configuration files
- Installs production policies
- Configures systemd service
- Mounts BPF filesystem
- Configures systemd-journald
- Enables (but doesn't start) service

### prerm (Pre-removal)
- Stops pepctl service
- Disables service (on removal, not upgrade)

### postrm (Post-removal)
- **remove**: Cleans eBPF resources, removes runtime dirs
- **purge**: Complete cleanup including config, policies, user/group

## Configuration Management

### Main Configuration
- **Source**: `configs/production.json`
- **Installed to**: `/etc/pepctl/pepctl.conf`
- **Features**:
  - systemd-journald logging only
  - Auto interface detection
  - Production-ready paths

### Policies
- **Source**: `policies/production.json`
- **Installed to**: `/etc/pepctl/policies/production.json`
- **Referenced by**: `/etc/pepctl/pepctl.conf`

### Backup Strategy
- Existing configs backed up with timestamp
- New defaults available in `/usr/share/pepctl/`
- Manual merge required for upgrades

## Service Management

### Installation
```bash
sudo dpkg -i pepctl_1.0.0-1_amd64.deb
sudo systemctl start pepctl
sudo systemctl status pepctl
```

### Logs
```bash
# View logs (systemd-journald only)
journalctl -u pepctl -f

# Check service status
systemctl status pepctl
```

### Configuration
```bash
# Edit main config
sudo nano /etc/pepctl/pepctl.conf

# Edit policies
sudo nano /etc/pepctl/policies/production.json

# Restart after changes
sudo systemctl restart pepctl
```

## eBPF Resource Management

### Automatic Cleanup
- Package scripts automatically clean eBPF resources
- XDP programs removed from all interfaces
- TC qdiscs cleaned up
- Pinned BPF maps removed

### BTF Support
- Package checks for BTF availability
- Warns if BTF not available
- Enables BPF statistics if supported

### BPF Filesystem
- Automatically mounts `/sys/fs/bpf`
- Adds to `/etc/fstab` for persistence
- Configures memory limits

## Security Features

### User/Group Management
- Creates system user `pepctl`
- Home directory: `/run/pepctl`
- No shell access
- Proper file permissions

### Systemd Security
- Runs as root (required for eBPF)
- Limited capabilities
- Protected system directories
- Private tmp directory

### File Permissions
```
/etc/pepctl/pepctl.conf         640 root:pepctl
/etc/pepctl/policies/           755 root:pepctl
/etc/pepctl/policies/*.json     640 root:pepctl
/run/pepctl/                    755 pepctl:pepctl
```

## Troubleshooting

### Build Issues
```bash
# Check dependencies
dpkg-checkbuilddeps

# Clean build
debian/rules clean
dpkg-buildpackage -us -uc -b
```

### Installation Issues
```bash
# Check package contents
dpkg -L pepctl

# Verify service
systemctl status pepctl
journalctl -u pepctl --no-pager

# Check eBPF resources
ls -la /sys/fs/bpf/
ip link show | grep xdp
```

### Removal Issues
```bash
# Complete removal
sudo apt-get purge pepctl

# Manual cleanup if needed
sudo rm -rf /etc/pepctl
sudo userdel pepctl
sudo groupdel pepctl
```

## Package Dependencies

### Runtime Dependencies
- libbpf0 (>= 0.5)
- libelf1
- libboost-system, libboost-filesystem, libboost-thread, libboost-program-options
- libspdlog1
- libfmt9 | libfmt8
- libsystemd0
- systemd

### Recommended Packages
- linux-tools-generic (for bpftool)
- bpftool

### Suggested Packages
- wireshark
- tcpdump
- netcat-openbsd

## Version Management

Current version: 1.0.0-1
- Major.Minor.Patch-DebianRevision
- Update `packaging/debian/changelog` for new versions
- Update `CMakeLists.txt` project version 