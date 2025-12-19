#!/bin/bash

# PEPCTL Build Script
# Comprehensive build system for all PEPCTL components

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_DIR="$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Build configuration
BUILD_TYPE="Release"
ENABLE_TESTS="ON"
ENABLE_COVERAGE="OFF"
PARALLEL_JOBS=$(nproc)
VERBOSE=false
CLEAN_BUILD=false

# Presets
USE_PRESETS=true
CONFIGURE_PRESET=""
BUILD_PRESET=""

# Toolchain / generator
GENERATOR="Ninja"
C_COMPILER="clang"
CXX_COMPILER="clang++"

resolve_build_dir() {
if [[ "$BUILD_TYPE" == "Debug" ]]; then
echo "$PROJECT_ROOT/build-ninja"
else
echo "$PROJECT_ROOT/build-ninja-release"
fi
}

resolve_default_presets() {
if [[ -n "$CONFIGURE_PRESET" ]]; then
return 0
fi

if [[ "$BUILD_TYPE" == "Debug" ]]; then
CONFIGURE_PRESET="clang-ninja-debug"
BUILD_PRESET="build-debug"
else
CONFIGURE_PRESET="clang-ninja-release"
BUILD_PRESET="build-release"
fi
}

# Available targets
ALL_TARGETS=(
"pepctl_core"
"pepctl_policy" 
"pepctl_ebpf"
"pepctl_metrics"
"pepctl_logger"
"pepctl"
"pepctl_tests"
"pepctl_integration_test"
"pepctl_test_client"
)

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

log_debug() {
echo -e "${BLUE}[DEBUG]${NC} $1"
}

log_success() {
echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_build() {
echo -e "${CYAN}[BUILD]${NC} $1"
}

# Show usage information
show_usage() {
cat << EOF
PEPCTL Build Script

Usage: $0 [OPTIONS] [TARGETS...]

OPTIONS:
-h, --help Show this help message
-d, --debug Build in Debug mode (default: Release)
-c, --clean Clean build directory before building
-t, --enable-tests Enable tests (default: ON)
-T, --disable-tests Disable tests
-v, --verbose Verbose build output
-j, --jobs N Number of parallel jobs (default: $(nproc))
--coverage Enable code coverage
--preset NAME Use a specific CMake configure preset (default: auto)
--build-preset NAME Use a specific CMake build preset (default: auto)
--no-presets Do not use CMakePresets.json (fallback to explicit -D flags)
--install-deps Install build dependencies before building
--list-targets List all available targets

TARGETS:
all Build all targets (default)
core Build core libraries only
tests Build all tests
main Build main pepctl executable
libs Build all libraries
integration Build integration tests

Individual targets:
$(printf " %-20s %s\n" "${ALL_TARGETS[@]}")

EXAMPLES:
$0 # Build everything in Release mode
$0 --debug core # Build core libraries in Debug mode
$0 --clean tests # Clean build and build tests
$0 -j 8 pepctl # Build main executable with 8 parallel jobs
$0 --verbose tests # Build tests with verbose output
$0 libs tests # Build libraries and tests
$0 --preset clang-ninja-debug --build-preset build-debug tests

BUILD TYPES:
Release Optimized build (-O3, no debug info)
Debug Debug build (-g, no optimization)
RelWithDebInfo Release with debug info (-O2 -g)
MinSizeRel Minimal size release (-Os)

EOF
}

# List all available targets
list_targets() {
log_info "Available build targets:"
echo
echo "Target Groups:"
echo " all - Build everything"
echo " core - pepctl_core pepctl_policy pepctl_ebpf pepctl_metrics pepctl_logger"
echo " libs - All libraries (same as core)"
echo " main - pepctl executable"
echo " tests - pepctl_tests pepctl_integration_test pepctl_test_client"
echo " integration - pepctl_integration_test pepctl_test_client"
echo
echo "Individual Targets:"
for target in "${ALL_TARGETS[@]}"; do
echo " $target"
done
}

# Check prerequisites
check_prerequisites() {
log_info "Checking build prerequisites..."

# Check required tools
local required_tools=("cmake" "ninja" "clang" "clang++" "pkg-config")
for tool in "${required_tools[@]}"; do
if ! command -v "$tool" >/dev/null 2>&1; then
log_error "Required tool '$tool' not found"
log_info "Please install build dependencies: ./scripts/install_deps.sh"
exit 1
fi
done

# Check CMake version
local cmake_version=$(cmake --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
local required_version="3.20"
if ! printf '%s\n%s\n' "$required_version" "$cmake_version" | sort -V -C; then
log_error "CMake version $cmake_version is too old (required: $required_version+)"
exit 1
fi

log_success "All prerequisites satisfied"
}

# Setup build directory
setup_build_dir() {
BUILD_DIR="$(resolve_build_dir)"
log_info "Setting up build directory: $BUILD_DIR"

if [[ "$CLEAN_BUILD" == "true" ]]; then
log_warn "Cleaning build directory..."
rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
}

# Configure CMake
configure_cmake() {
log_info "Configuring CMake (Build Type: $BUILD_TYPE)"

if [[ "$USE_PRESETS" == "true" ]]; then
resolve_default_presets

local cmake_args=("--preset" "$CONFIGURE_PRESET")

# Keep script toggles usable even when the preset has different defaults.
cmake_args+=("-DENABLE_TESTS=$ENABLE_TESTS")
cmake_args+=("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")

if [[ "$ENABLE_COVERAGE" == "ON" ]]; then
cmake_args+=("-DENABLE_COVERAGE=ON")
log_info "Code coverage enabled"
fi

if [[ "$VERBOSE" == "true" ]]; then
cmake_args+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
fi

log_debug "CMake command: cmake ${cmake_args[*]}"

if ! (cd "$PROJECT_ROOT" && cmake "${cmake_args[@]}"); then
log_error "CMake configuration failed"
exit 1
fi
else
local cmake_args=(
"-G" "$GENERATOR"
"-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
"-DCMAKE_C_COMPILER=$C_COMPILER"
"-DCMAKE_CXX_COMPILER=$CXX_COMPILER"
"-DENABLE_TESTS=$ENABLE_TESTS"
"-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
)

if [[ "$ENABLE_COVERAGE" == "ON" ]]; then
cmake_args+=("-DENABLE_COVERAGE=ON")
log_info "Code coverage enabled"
fi

if [[ "$VERBOSE" == "true" ]]; then
cmake_args+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
fi

log_debug "CMake command: cmake ${cmake_args[*]} -S $SOURCE_DIR -B $BUILD_DIR"

if ! cmake "${cmake_args[@]}" -S "$SOURCE_DIR" -B "$BUILD_DIR"; then
log_error "CMake configuration failed"
exit 1
fi
fi

log_success "CMake configuration completed"
}

# Build specific targets
build_targets() {
local targets=("$@")

if [[ ${#targets[@]} -eq 0 ]]; then
targets=("all")
fi

# Expand target groups
local expanded_targets=()
for target in "${targets[@]}"; do
case "$target" in
"all")
expanded_targets=("${ALL_TARGETS[@]}")
;;
"core"|"libs")
expanded_targets+=("pepctl_core" "pepctl_policy" "pepctl_ebpf" "pepctl_metrics" "pepctl_logger")
;;
"main")
expanded_targets+=("pepctl")
;;
"tests")
expanded_targets+=("pepctl_tests" "pepctl_integration_test" "pepctl_test_client")
;;
"integration")
expanded_targets+=("pepctl_integration_test" "pepctl_test_client")
;;
*)
expanded_targets+=("$target")
;;
esac
done

# Remove duplicates
local unique_targets=($(printf "%s\n" "${expanded_targets[@]}" | sort -u))

log_info "Building targets: ${unique_targets[*]}"

local failed_targets=()
local successful_targets=()

for target in "${unique_targets[@]}"; do
log_build "Building $target..."

if [[ "$USE_PRESETS" == "true" ]]; then
resolve_default_presets
if [[ -z "$BUILD_PRESET" ]]; then
log_error "Build preset is required when using presets"
return 1
fi

if cmake --build --preset "$BUILD_PRESET" --target "$target" --parallel "$PARALLEL_JOBS"; then
log_success " $target built successfully"
successful_targets+=("$target")
else
log_error " Failed to build $target"
failed_targets+=("$target")
fi
else
if cmake --build "$BUILD_DIR" --target "$target" --parallel "$PARALLEL_JOBS"; then
log_success " $target built successfully"
successful_targets+=("$target")
else
log_error " Failed to build $target"
failed_targets+=("$target")
fi
fi
done

# Build summary
echo
log_info "Build Summary:"
echo " Successful: ${#successful_targets[@]}"
echo " Failed: ${#failed_targets[@]}"

if [[ ${#successful_targets[@]} -gt 0 ]]; then
echo
log_success "Successfully built:"
for target in "${successful_targets[@]}"; do
echo " $target"
done
fi

if [[ ${#failed_targets[@]} -gt 0 ]]; then
echo
log_error "Failed to build:"
for target in "${failed_targets[@]}"; do
echo " $target"
done
return 1
fi

return 0
}

# Show build information
show_build_info() {
local source_short=$(basename "$SOURCE_DIR")
local build_dir_effective="$BUILD_DIR"
if [[ -z "$build_dir_effective" ]]; then
build_dir_effective="$(resolve_build_dir)"
fi
local build_short=$(basename "$build_dir_effective")

log_info "Build Information:"
echo " Project: PEPCTL eBPF Network Security Framework"
echo " Source: .../$source_short"
echo " Build: .../$build_short"
echo " Type: $BUILD_TYPE"
echo " Tests: $ENABLE_TESTS"
echo " Coverage: $ENABLE_COVERAGE"
echo " Jobs: $PARALLEL_JOBS"
echo " Verbose: $VERBOSE"
echo " Clean: $CLEAN_BUILD"
echo

if [[ "$VERBOSE" == "true" ]]; then
log_debug "Full paths:"
log_debug " Source: $SOURCE_DIR"
log_debug " Build: $build_dir_effective"
echo
fi
}

# Main execution
main() {
local targets=()

# Parse command line arguments
while [[ $# -gt 0 ]]; do
case $1 in
-h|--help)
show_usage
exit 0
;;
-d|--debug)
BUILD_TYPE="Debug"
shift
;;
-c|--clean)
CLEAN_BUILD=true
shift
;;
-t|--enable-tests)
ENABLE_TESTS="ON"
shift
;;
-T|--disable-tests)
ENABLE_TESTS="OFF"
shift
;;
-v|--verbose)
VERBOSE=true
shift
;;
-j|--jobs)
PARALLEL_JOBS="$2"
shift 2
;;
--coverage)
ENABLE_COVERAGE="ON"
BUILD_TYPE="Debug" # Coverage requires debug info
shift
;;
--preset)
CONFIGURE_PRESET="$2"
shift 2
;;
--build-preset)
BUILD_PRESET="$2"
shift 2
;;
--no-presets)
USE_PRESETS=false
shift
;;
--install-deps)
./scripts/install_deps.sh
shift
;;
--list-targets)
list_targets
exit 0
;;
-*)
log_error "Unknown option: $1"
echo "Use --help for usage information"
exit 1
;;
*)
targets+=("$1")
shift
;;
esac
done

# Resolve BUILD_DIR early (for display + clean) after parsing options.
BUILD_DIR="$(resolve_build_dir)"

# Show banner
echo
echo "═══════════════════════════════════════════════════════════════"
echo " PEPCTL Build System"
echo "═══════════════════════════════════════════════════════════════"
echo

show_build_info
check_prerequisites
setup_build_dir
configure_cmake

if build_targets "${targets[@]}"; then
echo
log_success "Build completed successfully!"

# Show build artifacts with better organization
echo
log_info "Build Artifacts:"

# Main executable
if [[ -f "$BUILD_DIR/src/pepctl" ]]; then
echo " Main: $BUILD_DIR/src/pepctl"
fi

# Libraries
local lib_count=0
for lib in "$BUILD_DIR/src/"libpepctl_*.so; do
if [[ -f "$lib" ]]; then
if [[ $lib_count -eq 0 ]]; then
echo " Libraries:"
fi
echo " - $(basename "$lib")"
((lib_count++))
fi
done

if [[ $lib_count -eq 0 ]]; then
# Check if any libraries exist at all
local any_libs=$(find "$BUILD_DIR" -name "libpepctl_*.so" 2>/dev/null | wc -l)
if [[ $any_libs -gt 0 ]]; then
echo " Libraries: $any_libs shared libraries built"
fi
fi

# Tests
if [[ -d "$BUILD_DIR/tests" ]]; then
echo " Tests: $BUILD_DIR/tests/"

# Count test executables
local test_count=$(find "$BUILD_DIR/tests" -name "*test*" -type f -executable 2>/dev/null | wc -l)
if [[ $test_count -gt 0 ]]; then
echo " - $test_count test executables found"
fi
fi

# eBPF programs
if [[ -d "$BUILD_DIR/ebpf" ]]; then
local ebpf_count=$(find "$BUILD_DIR/ebpf" -name "*.o" 2>/dev/null | wc -l)
if [[ $ebpf_count -gt 0 ]]; then
echo " eBPF: $ebpf_count compiled programs"
fi
fi

# Development tools
if [[ -f "$BUILD_DIR/compile_commands.json" ]]; then
echo " IDE Support: compile_commands.json"
fi

else
echo
log_error "Build failed!"
echo
log_info "Troubleshooting tips:"
echo " - Check dependencies: ./scripts/install_deps.sh"
echo " - Try clean build: ./scripts/build.sh --clean"
echo " - Enable verbose: ./scripts/build.sh --verbose"
echo " - Check logs above for specific errors"
exit 1
fi
}

# Run main function
main "$@" 