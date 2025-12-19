#!/bin/bash

# PEPCTL Professional DEB Package Generator
# Uses the new packaging/debian/ structure with dpkg-buildpackage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

log_success() {
echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_package() {
echo -e "${BLUE}[PACKAGE]${NC} $1"
}

# Show usage information
show_usage() {
cat << EOF
${PURPLE}PEPCTL Professional DEB Package Generator${NC}

Usage: $0 [OPTIONS]

${YELLOW}OPTIONS:${NC}
    -h, --help              Show this help message
    -v, --version VERSION   Update version before building
    -r, --revision REV      Set Debian revision (default: 1)
    --build                 Build project before packaging
    --clean                 Clean build artifacts before packaging
    --fast                  Use existing build (faster, requires prior build)
    --no-deps               Skip dependency checks
    --source                Build source package instead of binary
    --unsigned              Build unsigned package (for testing)
    --check-version         Check version consistency
    --show-info             Show package information

${YELLOW}EXAMPLES:${NC}
    $0                      # Build package with current version
    $0 --build              # Build project and create package
    $0 -v 1.1.0             # Update to version 1.1.0 and build package
    $0 -v 1.1.0 -r 2        # Update to version 1.1.0-2 and build package
    $0 --clean --build      # Clean, build, and package
    $0 --source             # Build source package
    $0 --check-version      # Check version consistency

${YELLOW}PACKAGE STRUCTURE:${NC}
    Uses professional Debian packaging with:
    - packaging/debian/control (dependencies)
    - packaging/debian/rules (build rules)
    - packaging/debian/preinst, postinst, prerm, postrm (maintainer scripts)
    - packaging/debian/changelog (version history)

EOF
}

# Check prerequisites
check_prerequisites() {
log_info "Checking packaging prerequisites..."

# Check required tools
    local required_tools=("dpkg-buildpackage" "dpkg-parsechangelog" "dh")
for tool in "${required_tools[@]}"; do
if ! command -v "$tool" >/dev/null 2>&1; then
log_error "Required tool '$tool' not found"
            log_info "Install with: sudo apt-get install dpkg-dev debhelper"
exit 1
fi
done

    # Check if packaging directory exists
    if [[ ! -d "$PROJECT_ROOT/packaging/debian" ]]; then
        log_error "Debian packaging directory not found: $PROJECT_ROOT/packaging/debian"
        log_info "The professional packaging structure is missing"
exit 1
fi

    # Check required packaging files
    local required_files=("control" "rules" "changelog")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$PROJECT_ROOT/packaging/debian/$file" ]]; then
            log_error "Required packaging file missing: packaging/debian/$file"
            exit 1
        fi
    done

log_success "All prerequisites satisfied"
}

# Check build dependencies
check_build_deps() {
    log_info "Checking build dependencies..."
    
    cd "$PROJECT_ROOT"
    if ! dpkg-checkbuilddeps packaging/debian/control 2>/dev/null; then
        log_warn "Some build dependencies are missing"
        log_info "Install with: sudo apt-get build-dep ."
        log_info "Or install manually: sudo apt-get install cmake build-essential pkg-config libbpf-dev libelf-dev libboost-all-dev nlohmann-json3-dev libspdlog-dev libfmt-dev libsystemd-dev linux-headers-generic"
        
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_success "All build dependencies satisfied"
    fi
}

# Show package information
show_package_info() {
    log_info "Package Information:"
    echo "===================="
    
    cd "$PROJECT_ROOT"
    
    # Get version information
    local cmake_version=$(grep "project.*VERSION" CMakeLists.txt | sed -n 's/.*VERSION \([0-9.]*\).*/\1/p')
    local deb_version=$(dpkg-parsechangelog -l packaging/debian/changelog -S Version 2>/dev/null || echo "Unknown")
    
    echo "CMake version: $cmake_version"
    echo "Debian version: $deb_version"
    echo "Package name: $(dpkg-parsechangelog -l packaging/debian/changelog -S Source 2>/dev/null || echo "pepctl")"
    echo "Maintainer: $(dpkg-parsechangelog -l packaging/debian/changelog -S Maintainer 2>/dev/null || echo "Unknown")"
    echo ""
    
    # Show package files that will be created
    echo "Package files will be created in parent directory:"
    echo "- pepctl_${deb_version}_amd64.deb (binary package)"
    echo "- pepctl_${deb_version}_amd64.changes (changes file)"
    echo "- pepctl_${deb_version}.tar.xz (source archive, if --source used)"
    echo ""
}

# Update version
update_version() {
    local new_version="$1"
    local debian_revision="${2:-1}"
    
    log_info "Updating version to $new_version-$debian_revision..."
    
    if [[ -x "$PROJECT_ROOT/scripts/update-version.sh" ]]; then
        "$PROJECT_ROOT/scripts/update-version.sh" update "$new_version" "$debian_revision"
    else
        log_error "Version update script not found or not executable"
        exit 1
    fi
}

# Check version consistency
check_version_consistency() {
    log_info "Checking version consistency..."
    
    if [[ -x "$PROJECT_ROOT/scripts/update-version.sh" ]]; then
        "$PROJECT_ROOT/scripts/update-version.sh" check
    else
        log_warn "Version check script not found"
    fi
}

# Clean build artifacts
clean_build() {
    log_info "Cleaning build artifacts..."
    
    cd "$PROJECT_ROOT"
    
    # Clean CMake build
    if [[ -d "build-ninja" ]]; then
        rm -rf build-ninja
        log_info "Removed build-ninja directory"
    fi

    if [[ -d "build-ninja-release" ]]; then
        rm -rf build-ninja-release
        log_info "Removed build-ninja-release directory"
    fi
    
    # Clean Debian build artifacts
    rm -f ../*.deb ../*.changes ../*.tar.* ../*.dsc ../*.buildinfo 2>/dev/null || true
    
    # Clean packaging artifacts
    rm -rf debian 2>/dev/null || true
    
    log_success "Build artifacts cleaned"
}

# Build project
build_project() {
    log_info "Building PEPCTL project..."
    
    cd "$PROJECT_ROOT"
    
    if [[ -x "scripts/build.sh" ]]; then
        ./scripts/build.sh
    else
        # Fallback to manual build
        mkdir -p build-ninja-release
        cd build-ninja-release
        cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=OFF \
            -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
        cmake --build . --parallel "$(nproc)"
        cd ..
    fi
    
    log_success "Project built successfully"
}

# Build DEB package
build_deb_package() {
    local build_source="$1"
    local unsigned="$2"
    
    log_package "Building Debian package..."
    
    cd "$PROJECT_ROOT"
    
    # Copy debian directory to project root (required by dpkg-buildpackage)
    if [[ -d "debian" ]]; then
        rm -rf debian
    fi
    cp -r packaging/debian .
    
    # Build package
    local dpkg_opts=""
    
    if [[ "$build_source" == "true" ]]; then
        dpkg_opts="-S"
        log_info "Building source package..."
    else
        dpkg_opts="-b"
        log_info "Building binary package..."
    fi
    
    if [[ "$unsigned" == "true" ]]; then
        dpkg_opts="$dpkg_opts -us -uc"
        log_info "Building unsigned package (for testing)"
    fi
    
    # Build the package
    if dpkg-buildpackage $dpkg_opts; then
        log_success "Package built successfully"
        
        # Create dist directory and move packages
        mkdir -p dist
        mv ../pepctl_* dist/ 2>/dev/null || true
        
        # Clean up build artifacts
        rm -rf debian obj-* 2>/dev/null || true
        
        log_success "Packages moved to dist/ directory:"
        ls -la dist/pepctl_*
    else
        log_error "Package build failed"
        return 1
    fi
}

# Build DEB package using existing build
build_deb_package_fast() {
    local build_source="$1"
    local unsigned="$2"
    
    log_package "Building Debian package using existing build..."
    
    cd "$PROJECT_ROOT"
    
    # Check if we have existing build
    if [[ ! -d "build-ninja-release" ]] || [[ ! -f "build-ninja-release/src/pepctl" ]]; then
        log_error "No existing build found. Run './scripts/build.sh' first or use --build flag"
        return 1
    fi
    
    # Create temporary debian directory structure
    mkdir -p debian/pepctl
    
    # Install binaries and libraries from existing build
    log_info "Installing from existing build directory..."
    
    # Install main executable
    install -d debian/pepctl/usr/bin
    install -m 755 build-ninja-release/src/pepctl debian/pepctl/usr/bin/
    
    # Install shared libraries
    install -d debian/pepctl/usr/lib
    find build-ninja-release/src -name "*.so" -exec install -m 644 {} debian/pepctl/usr/lib/ \;
    
    # Install eBPF programs
    install -d debian/pepctl/usr/share/pepctl/ebpf
    install -m 644 build-ninja-release/ebpf/*.o debian/pepctl/usr/share/pepctl/ebpf/
    
    # Install configuration files
    install -d debian/pepctl/usr/share/pepctl
    install -m 644 configs/*.json debian/pepctl/usr/share/pepctl/
    
    # Install policy examples
    install -d debian/pepctl/usr/share/pepctl/policies
    install -m 644 policies/*.json debian/pepctl/usr/share/pepctl/policies/
    
    # Install systemd service
    install -d debian/pepctl/lib/systemd/system
    install -m 644 systemd/pepctl.service debian/pepctl/lib/systemd/system/
    
    # Install documentation
    install -d debian/pepctl/usr/share/doc/pepctl
    install -m 644 README.md debian/pepctl/usr/share/doc/pepctl/
    
    # Install version information
    local pkg_version
    pkg_version="$(tr -d '\r\n' < VERSION | tr -d '[:space:]')"
    echo "$pkg_version" > debian/pepctl/usr/share/pepctl/VERSION
    echo "$pkg_version-1" > debian/pepctl/usr/share/pepctl/DEB_VERSION
    
    # Copy packaging control files
    cp -r packaging/debian/* debian/
    
    # Create DEBIAN directory and copy maintainer scripts
    install -d debian/pepctl/DEBIAN
    for script in preinst postinst prerm postrm; do
        if [[ -f "packaging/debian/$script" ]]; then
            install -m 755 "packaging/debian/$script" "debian/pepctl/DEBIAN/"
        fi
    done
    
    # Generate control file with proper dependencies
    log_info "Generating package control file..."
    
    # Create control file
    cat > debian/pepctl/DEBIAN/control << EOF
Package: pepctl
Version: ${pkg_version}-1
Architecture: amd64
Maintainer: PEPCTL Development Team <dev@pepctl.org>
Installed-Size: $(du -sk debian/pepctl | cut -f1)
Depends: libbpf1, libelf1, libboost-system1.83.0, libboost-filesystem1.83.0, libboost-thread1.83.0, libboost-program-options1.83.0, libspdlog1, libfmt9, systemd, libc6, libstdc++6
Recommends: linux-tools-generic, bpftool
Suggests: wireshark, tcpdump, netcat-openbsd
Section: net
Priority: optional
Homepage: https://github.com/pepctl/pepctl
Description: Policy Enforcement Point Control Utility
 PEPCTL is a high-performance Policy Enforcement Point (PEP) daemon built in
 modern C++ that provides real-time network packet filtering and policy
 enforcement using eBPF technology.
 .
 Key features:
  * eBPF-based packet processing for high performance
  * Dynamic policy management with runtime updates
  * Lock-free architecture optimized for multi-threading
  * Real-time metrics with Prometheus integration
  * Comprehensive logging with systemd journal integration
  * Modern C++20 implementation with best practices
 .
 This package includes the main daemon, configuration files, systemd service
 integration, and comprehensive documentation.
EOF
    
    # Build the package
    log_info "Creating .deb package..."
    mkdir -p dist
    
    if dpkg-deb --build "debian/pepctl" "dist/pepctl_${pkg_version}-1_amd64.deb"; then
        log_success "Package built successfully using existing build!"
        
        # Clean up temporary files
        rm -rf debian
        
        log_success "Package created: dist/pepctl_${pkg_version}-1_amd64.deb"
        ls -la dist/pepctl_*
    else
        log_error "Package build failed"
        return 1
    fi
}

# Main script logic
main() {
    local version=""
    local revision="1"
    local build_project_flag=false
    local clean_flag=false
    local no_deps=false
    local build_source=false
    local unsigned=true  # Default to unsigned for development
    local check_version_flag=false
    local show_info_flag=false
    local fast_build=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
case $1 in
-h|--help)
show_usage
exit 0
;;
-v|--version)
                version="$2"
shift 2
;;
-r|--revision)
                revision="$2"
shift 2
;;
--build)
                build_project_flag=true
shift
;;
--clean)
                clean_flag=true
shift
;;
--fast)
                fast_build=true
shift
;;
--no-deps)
                no_deps=true
                shift
                ;;
            --source)
                build_source=true
                shift
                ;;
            --unsigned)
                unsigned=true
                shift
                ;;
            --signed)
                unsigned=false
                shift
                ;;
            --check-version)
                check_version_flag=true
shift
;;
            --show-info)
                show_info_flag=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
exit 1
;;
esac
done

    # Show package info if requested
    if [[ "$show_info_flag" == "true" ]]; then
        show_package_info
        exit 0
    fi
    
    # Check version consistency if requested
    if [[ "$check_version_flag" == "true" ]]; then
        check_version_consistency
        exit 0
fi

# Check prerequisites
check_prerequisites

    # Check build dependencies unless skipped
    if [[ "$no_deps" != "true" ]]; then
        check_build_deps
    fi

    # Update version if specified
    if [[ -n "$version" ]]; then
        update_version "$version" "$revision"
    fi

    # Clean if requested
    if [[ "$clean_flag" == "true" ]]; then
        clean_build
    fi

    # Build project if requested
    if [[ "$build_project_flag" == "true" ]]; then
        build_project
    fi

    # Show package information
    show_package_info

    # Build package
    if [[ "$fast_build" == "true" ]]; then
        build_deb_package_fast "$build_source" "$unsigned"
    else
        build_deb_package "$build_source" "$unsigned"
    fi

    log_success "PEPCTL Debian package creation completed!"
}

# Run main function with all arguments
main "$@" 