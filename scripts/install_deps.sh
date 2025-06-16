#!/bin/bash

# PEPCTL Dependencies Installation Script
# Installs all required dependencies for building and running pepctl

# Note: Removed 'set -e' to allow custom error handling

# Colors for output
# \033 is \e (escape) + control sequence introducer (CSI) + text attribute (1 = bold/bright) + 
# ; - separator +
# color code + 
# end sequence (reset) - m
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {

echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
echo -e "${BLUE}[STEP]${NC} $1"
}

# Detect OS
detect_os() {
if [ -f /etc/os-release ]; then
. /etc/os-release
OS=$ID
OS_VERSION=$VERSION_ID
log_info "Detected OS: $OS $OS_VERSION"
return 0
else
log_error "Cannot detect OS version - /etc/os-release not found"
return 1
fi
}

# Check if running as root
check_root() {
if [ "$EUID" -ne 0 ]; then
log_error "This script must be run as root"
log_info "Please run: sudo $0"
return 1
fi
return 0
}

# Update package lists
update_packages() {
log_step "Updating package lists..."

case $OS in
ubuntu|debian)
if apt-get update; then
return 0
else
log_error "Failed to update apt package lists"
return 1
fi
;;
fedora|centos|rhel)
if dnf update -y || yum update -y; then
return 0
else
log_error "Failed to update dnf/yum package lists"
return 1
fi
;;
*)
log_warn "Unknown OS, skipping package update"
return 0
;;
esac
}

# Install basic build tools
install_build_tools() {
log_step "Installing basic build tools..."

case $OS in
ubuntu|debian)
if apt-get install -y \
build-essential \
cmake \
git \
pkg-config \
curl \
wget; then
return 0
else
log_error "Failed to install build tools on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf install -y \
gcc \
gcc-c++ \
cmake \
git \
pkgconfig \
curl \
wget || \
yum install -y \
gcc \
gcc-c++ \
cmake \
git \
pkgconfig \
curl \
wget; then
return 0
else
log_error "Failed to install build tools on Fedora/CentOS/RHEL"
return 1
fi
;;
*)
log_error "Unsupported OS for automatic installation"
return 1
;;
esac
}

# Install eBPF dependencies
install_ebpf_deps() {
log_step "Installing eBPF dependencies..."

case $OS in
ubuntu|debian)
if apt-get install -y \
libbpf-dev \
libelf-dev \
clang \
llvm \
linux-headers-$(uname -r) \
linux-tools-$(uname -r) \
linux-tools-common; then
return 0
else
log_error "Failed to install eBPF dependencies on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf install -y \
libbpf-devel \
elfutils-libelf-devel \
clang \
llvm \
kernel-headers \
kernel-devel \
bpftool || \
yum install -y \
libbpf-devel \
elfutils-libelf-devel \
clang \
llvm \
kernel-headers \
kernel-devel; then
return 0
else
log_error "Failed to install eBPF dependencies on Fedora/CentOS/RHEL"
return 1
fi
;;
*)
log_error "Unsupported OS for eBPF dependencies"
return 1
;;
esac
}

# Install Boost libraries
install_boost() {
log_step "Installing Boost libraries..."

case $OS in
ubuntu|debian)
if apt-get install -y libboost-all-dev; then
return 0
else
log_error "Failed to install Boost on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf install -y boost-devel || yum install -y boost-devel; then
return 0
else
log_error "Failed to install Boost on Fedora/CentOS/RHEL"
return 1
fi
;;
*)
log_error "Unsupported OS for Boost installation"
return 1
;;
esac
}

# Install nlohmann-json
install_json() {
log_step "Installing nlohmann-json..."

case $OS in
ubuntu|debian)
if apt-get install -y nlohmann-json3-dev; then
return 0
else
log_error "Failed to install nlohmann-json on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
# nlohmann-json might not be available in older repos
if dnf list nlohmann-json-devel &>/dev/null || yum list nlohmann-json-devel &>/dev/null; then
if dnf install -y nlohmann-json-devel || yum install -y nlohmann-json-devel; then
return 0
else
log_error "Failed to install nlohmann-json on Fedora/CentOS/RHEL"
return 1
fi
else
log_warn "nlohmann-json not available in repos, will be downloaded by CMake"
return 0
fi
;;
*)
log_error "Unsupported OS for nlohmann-json installation"
return 1
;;
esac
}

# Install spdlog
install_spdlog() {
log_step "Installing spdlog..."

case $OS in
ubuntu|debian)
if apt-get install -y libspdlog-dev; then
return 0
else
log_error "Failed to install spdlog on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf list spdlog-devel &>/dev/null || yum list spdlog-devel &>/dev/null; then
if dnf install -y spdlog-devel || yum install -y spdlog-devel; then
return 0
else
log_error "Failed to install spdlog on Fedora/CentOS/RHEL"
return 1
fi
else
log_warn "spdlog not available in repos, will be built from source"
return 0
fi
;;
*)
log_error "Unsupported OS for spdlog installation"
return 1
;;
esac
}

# Install testing dependencies
install_test_deps() {
log_step "Installing testing dependencies..."

case $OS in
ubuntu|debian)
if apt-get install -y \
libgtest-dev \
googletest \
valgrind; then
return 0
else
log_error "Failed to install testing dependencies on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf install -y \
gtest-devel \
gmock-devel \
valgrind || \
yum install -y \
gtest-devel \
gmock-devel \
valgrind; then
return 0
else
log_error "Failed to install testing dependencies on Fedora/CentOS/RHEL"
return 1
fi
;;
*)
log_error "Unsupported OS for testing dependencies"
return 1
;;
esac
}

# Install runtime dependencies
install_runtime_deps() {
log_step "Installing runtime dependencies..."

case $OS in
ubuntu|debian)
if apt-get install -y \
systemd \
iproute2 \
net-tools \
tcpdump; then
return 0
else
log_error "Failed to install runtime dependencies on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf install -y \
systemd \
iproute \
net-tools \
tcpdump || \
yum install -y \
systemd \
iproute \
net-tools \
tcpdump; then
return 0
else
log_error "Failed to install runtime dependencies on Fedora/CentOS/RHEL"
return 1
fi
;;
*)
log_error "Unsupported OS for runtime dependencies"
return 1
;;
esac
}

# Install packaging dependencies
install_packaging_deps() {
log_step "Installing packaging dependencies..."

case $OS in
ubuntu|debian)
if apt-get install -y \
dpkg-dev \
debhelper \
debhelper-compat \
dh-systemd \
lintian \
fakeroot; then
return 0
else
log_error "Failed to install packaging dependencies on Ubuntu/Debian"
return 1
fi
;;
fedora|centos|rhel)
if dnf install -y \
rpm-build \
rpm-devel \
rpmdevtools \
rpmlint || \
yum install -y \
rpm-build \
rpm-devel \
rpmdevtools \
rpmlint; then
return 0
else
log_error "Failed to install packaging dependencies on Fedora/CentOS/RHEL"
return 1
fi
;;
*)
log_error "Unsupported OS for packaging dependencies"
return 1
;;
esac
}

# Create necessary directories
create_directories() {
log_step "Creating necessary directories..."

if mkdir -p /etc/pepctl /var/log/pepctl /var/lib/pepctl /usr/share/pepctl; then
# Set proper permissions
if chmod 755 /etc/pepctl /var/log/pepctl /var/lib/pepctl /usr/share/pepctl; then
log_info "Created directories with proper permissions"
return 0
else
log_error "Failed to set directory permissions"
return 1
fi
else
log_error "Failed to create necessary directories"
return 1
fi
}

# Verify installation
verify_installation() {
log_step "Verifying installation..."

local errors=0

# Check compilers
if ! which gcc >/dev/null 2>&1; then
log_error "GCC not found"
((errors++))
fi

if ! which clang >/dev/null 2>&1; then
log_error "Clang not found"
((errors++))
fi

if ! which cmake >/dev/null 2>&1; then
log_error "CMake not found"
((errors++))
fi

# Check libraries
if ! pkg-config --exists libbpf; then
log_error "libbpf not found"
((errors++))
fi

if ! pkg-config --exists libelf; then
log_error "libelf not found"
((errors++))
fi

# Check kernel headers
if [ ! -d "/lib/modules/$(uname -r)/build" ] && [ ! -d "/usr/src/linux-headers-$(uname -r)" ]; then
log_error "Kernel headers not found"
((errors++))
fi

# Check packaging tools
if ! which dpkg-buildpackage >/dev/null 2>&1; then
log_error "dpkg-buildpackage not found"
((errors++))
fi

if ! which debhelper >/dev/null 2>&1 && ! dpkg -l debhelper >/dev/null 2>&1; then
log_error "debhelper not found"
((errors++))
fi

if [ $errors -eq 0 ]; then
log_info " All dependencies verified successfully"
return 0
else
log_error " $errors dependency issues found"
return 1
fi
}

# Show installation summary
show_summary() {
log_info "Installation Summary:"
log_info "===================="
log_info "• Build tools: gcc, clang, cmake"
log_info "• eBPF: libbpf, libelf, bpftool"
log_info "• Libraries: Boost, nlohmann-json, spdlog"
log_info "• Testing: Google Test, Valgrind"
log_info "• Runtime: systemd, networking tools"
log_info "• Packaging: dpkg-dev, debhelper, lintian"
log_info ""
log_info "Next steps:"
log_info "1. Build the project: ./scripts/build.sh"
log_info "2. Run tests: ./scripts/build.sh --test"
log_info "3. Create package: ./scripts/package-deb.sh --build"
log_info "4. Install package: sudo dpkg -i ../pepctl_*.deb"
}

# Main installation function
main() {
log_info "PEPCTL Dependencies Installation"
log_info "==============================="

# Step 1: Detect OS
if ! detect_os; then
log_error " OS detection failed. Cannot proceed."
return 1
fi

# Step 2: Check root privileges
if ! check_root; then
log_error " Root privileges required. Please run with sudo."
return 1
fi

# Step 3: Update packages
if ! update_packages; then
log_error " Package update failed. Continuing anyway..."
# Don't exit here, continue with installation
fi

# Step 4: Install build tools
if ! install_build_tools; then
log_error " Build tools installation failed. Cannot proceed."
return 1
fi

# Step 5: Install eBPF dependencies
if ! install_ebpf_deps; then
log_error " eBPF dependencies installation failed. Cannot proceed."
return 1
fi

# Step 6: Install Boost
if ! install_boost; then
log_error " Boost installation failed. Cannot proceed."
return 1
fi

# Step 7: Install JSON library (non-critical)
if ! install_json; then
log_warn "️ JSON library installation failed. CMake will handle it."
# Continue anyway
fi

# Step 8: Install spdlog (non-critical)
if ! install_spdlog; then
log_warn "️ spdlog installation failed. Will be built from source."
# Continue anyway
fi

# Step 9: Install testing dependencies (non-critical)
if ! install_test_deps; then
log_warn "️ Testing dependencies installation failed. Tests may not work."
# Continue anyway
fi

# Step 10: Install runtime dependencies
if ! install_runtime_deps; then
log_error " Runtime dependencies installation failed. Cannot proceed."
return 1
fi

# Step 11: Install packaging dependencies
if ! install_packaging_deps; then
log_error " Packaging dependencies installation failed. Cannot proceed."
return 1
fi

# Step 12: Create directories
if ! create_directories; then
log_error " Directory creation failed. Cannot proceed."
return 1
fi

# Step 13: Verify installation
if verify_installation; then
show_summary
log_info " Dependencies installation completed successfully!"
return 0
else
log_error " Dependencies installation completed with issues"
log_info "Some dependencies may be missing. Check the errors above."
return 1
fi
}

# Run main function and exit with its return code
main "$@"
exit $? 