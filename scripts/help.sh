#!/bin/bash

# PEPCTL Scripts Help
# Shows all available scripts and their usage

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo
echo "═══════════════════════════════════════════════════════════════"
echo -e " ${PURPLE}PEPCTL Scripts Help${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo

echo -e "${GREEN} BUILD SCRIPTS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${CYAN}./scripts/build.sh${NC} - Comprehensive build system"
echo " Examples:"
echo " ./scripts/build.sh # Build everything"
echo " ./scripts/build.sh core # Build core libraries"
echo " ./scripts/build.sh tests # Build all tests"
echo " ./scripts/build.sh --debug --coverage # Debug build with coverage"
echo " ./scripts/build.sh --clean main # Clean build main executable"
echo

echo -e "${GREEN} TESTING SCRIPTS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${CYAN}./scripts/test.sh${NC} - Comprehensive test runner"
echo " Examples:"
echo " ./scripts/test.sh # Run all tests"
echo " ./scripts/test.sh unit # Unit tests only"
echo " sudo ./scripts/test.sh e2e # E2E tests (needs root)"
echo " ./scripts/test.sh --coverage unit # Unit tests with coverage"
echo " ./scripts/test.sh --valgrind unit # Memory checking"
echo

echo -e "${GREEN} PACKAGING SCRIPTS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${CYAN}./scripts/package-deb.sh${NC} - DEB package generator"
echo " Examples:"
echo " ./scripts/package-deb.sh --build # Build and package"
echo " ./scripts/package-deb.sh -v 1.1.0 # Custom version"
echo " ./scripts/package-deb.sh --clean # Clean package build"
echo

echo -e "${GREEN} UTILITY SCRIPTS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${CYAN}./scripts/install_deps.sh${NC} - Install build dependencies"
echo -e "${CYAN}./scripts/format-code.sh${NC} - Format code with clang-format"
echo -e "${CYAN}./scripts/explicit-bool-fix.sh${NC} - Fix explicit bool conversions"
echo -e "${CYAN}./scripts/convert-to-camelcase.sh${NC} - Convert to camelCase naming"
echo -e "${CYAN}./scripts/help.sh${NC} - Show this help (current script)"
echo

echo -e "${GREEN} QUICK START COMMANDS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${YELLOW}# Complete setup and build${NC}"
echo " ./scripts/install_deps.sh && ./scripts/build.sh"
echo
echo -e "${YELLOW}# Build and test everything${NC}"
echo " ./scripts/build.sh && ./scripts/test.sh"
echo
echo -e "${YELLOW}# Create production package${NC}"
echo " ./scripts/build.sh && ./scripts/package-deb.sh --build"
echo
echo -e "${YELLOW}# Development workflow${NC}"
echo " ./scripts/build.sh --debug tests"
echo " ./scripts/test.sh --coverage"
echo

echo -e "${GREEN} BUILD TARGETS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Target Groups:"
echo " all - Build everything (default)"
echo " core - Core libraries (pepctl_core, pepctl_policy, etc.)"
echo " libs - Same as core"
echo " main - Main pepctl executable"
echo " tests - All tests (unit, integration, test client)"
echo " e2e - End-to-end tests only"
echo " integration - Integration tests only"
echo
echo "Individual Targets:"
echo " pepctl_core, pepctl_policy, pepctl_ebpf, pepctl_metrics,"
echo " pepctl_logger, pepctl, pepctl_tests, pepctl_integration_test,"
echo " pepctl_test_client, pepctl_e2e_tests"
echo

echo -e "${GREEN} TEST TYPES${NC}"
echo "────────────────────────────────────────────────────────────────"
echo " unit - Unit tests (~10 seconds)"
echo " integration - Integration tests (~30 seconds)"
echo " e2e - End-to-end tests (~90 seconds, requires root)"
echo " all - All test types (default)"
echo

echo -e "${GREEN} COMMON OPTIONS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Build Options:"
echo " --debug - Debug build (-g, no optimization)"
echo " --clean - Clean build directory first"
echo " --verbose - Verbose build output"
echo " --coverage - Enable code coverage"
echo " -j N - Use N parallel jobs"
echo
echo "Test Options:"
echo " --verbose - Verbose test output"
echo " --coverage - Generate coverage report"
echo " --valgrind - Run with memory checking"
echo " --filter - Filter tests by pattern"
echo " --xml/--json - Generate XML/JSON reports"
echo

echo -e "${GREEN} PERFORMANCE TIPS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo " • Use -j \$(nproc) for parallel builds (done automatically)"
echo " • Build specific targets to save time: ./scripts/build.sh core"
echo " • Run unit tests during development: ./scripts/test.sh unit"
echo " • Use --coverage only when needed (slower builds)"
echo " • E2E tests require root but give comprehensive validation"
echo

echo -e "${GREEN} OUTPUT LOCATIONS${NC}"
echo "────────────────────────────────────────────────────────────────"
echo " build-ninja/ - Debug build artifacts"
echo " build-ninja/src/pepctl - Main executable (Debug)"
echo " build-ninja/tests/ - Test binaries (Debug)"
echo " build-ninja-release/ - Release build artifacts"
echo " build-ninja-release/src/pepctl - Main executable (Release)"
echo " package/ - DEB packages"
echo

echo -e "${GREEN} TROUBLESHOOTING${NC}"
echo "────────────────────────────────────────────────────────────────"
echo " • Build fails: Check ./scripts/install_deps.sh"
echo " • E2E tests fail: Run with sudo and check network namespaces"
echo " • Permission issues: Use sudo or check capabilities"
echo " • Memory issues: Use --valgrind for debugging"
echo " • Clean build: Use --clean option"
echo

echo "For detailed help on any script, run: SCRIPT_NAME --help"
echo "For project documentation, see: docs/ directory"
echo

# End of script 