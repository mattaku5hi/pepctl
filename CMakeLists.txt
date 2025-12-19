cmake_minimum_required(VERSION 3.20)
project(pepctl VERSION 1.0.0 LANGUAGES CXX C)

if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "pepctl requires Clang for C compiler (set -DCMAKE_C_COMPILER=clang)")
endif()

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "pepctl requires Clang for C++ compiler (set -DCMAKE_CXX_COMPILER=clang++)")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(ENABLE_TESTS "Enable building of test suites" ON)
option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)
option(ENABLE_SYSTEMD_NOTIFY "Enable systemd Type=notify support (sd_notify READY/STOPPING)" OFF)

# Enable debug symbols and optimization flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Coverage flags
if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --coverage")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem thread program_options)
find_package(Threads REQUIRED)

# eBPF dependencies
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)

# Logging dependencies
pkg_check_modules(SPDLOG REQUIRED spdlog)
pkg_check_modules(FMT REQUIRED fmt)
pkg_check_modules(LIBSYSTEMD REQUIRED libsystemd)

if(ENABLE_SYSTEMD_NOTIFY)
    add_definitions(-DSYSTEMD_NOTIFY_SUPPORT)
endif()

# JSON support for structured logging
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    pkg_check_modules(NLOHMANN_JSON REQUIRED nlohmann_json)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${LIBBPF_INCLUDE_DIRS})

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Add subdirectories
add_subdirectory(ebpf)  # eBPF programs must be compiled first
add_subdirectory(src)

# Conditionally add tests
if(ENABLE_TESTS)
    find_package(GTest QUIET)
    if(GTest_FOUND OR GTEST_FOUND)
        message(STATUS "Tests enabled - building test suites")
        add_subdirectory(tests)
    else()
        message(WARNING "Tests enabled but GoogleTest not found - skipping tests")
    endif()
else()
    message(STATUS "Tests disabled")
endif()

# Install systemd service
install(FILES systemd/pepctl.service DESTINATION /lib/systemd/system/)

# Install configuration files
install(FILES configs/production.json DESTINATION /usr/share/pepctl/)
install(FILES configs/development.json DESTINATION /usr/share/pepctl/)
install(FILES configs/testing.json DESTINATION /usr/share/pepctl/)

# Install policy examples
install(DIRECTORY policies/ DESTINATION /usr/share/pepctl/policies/
        FILES_MATCHING PATTERN "*.json")

# Install documentation
install(FILES README.md DESTINATION /usr/share/doc/pepctl/)

# Optional: Add custom targets for eBPF operations
if(TARGET verify_ebpf)
    add_custom_target(verify-all DEPENDS verify_ebpf)
endif()

if(TARGET ebpf_debug)
    add_custom_target(show-ebpf-config DEPENDS ebpf_debug)
endif()

# Print eBPF object files location for runtime
message(STATUS "eBPF object files will be available in: ${CMAKE_BINARY_DIR}/ebpf/")

# Development target to clean everything including eBPF
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMENT "Cleaning all build artifacts including eBPF programs"
)

# CPack configuration for Debian package generation
include(CPack)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "pepctl")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Policy Enforcement Point Control Utility")
set(CPACK_PACKAGE_DESCRIPTION "PEPCTL is a high-performance Policy Enforcement Point (PEP) daemon built in modern C++ that provides real-time network packet filtering and policy enforcement using eBPF technology.")
set(CPACK_PACKAGE_MAINTAINER "PEPCTL Development Team <dev@pepctl.org>")
set(CPACK_PACKAGE_SECTION "net")
set(CPACK_PACKAGE_PRIORITY "optional")

# Debian-specific settings
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbpf0 (>= 0.5), libelf1, libboost-system1.74.0 | libboost-system1.81.0, libboost-filesystem1.74.0 | libboost-filesystem1.81.0, libboost-thread1.74.0 | libboost-thread1.81.0, libboost-program-options1.74.0 | libboost-program-options1.81.0, libspdlog1, libfmt9 | libfmt8, libsystemd0, systemd")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "linux-tools-generic, bpftool")
set(CPACK_DEBIAN_PACKAGE_SUGGESTS "wireshark, tcpdump, netcat-openbsd")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/pepctl/pepctl")

# Use custom packaging directory if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/packaging/debian")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA 
        "${CMAKE_SOURCE_DIR}/packaging/debian/preinst"
        "${CMAKE_SOURCE_DIR}/packaging/debian/postinst"
        "${CMAKE_SOURCE_DIR}/packaging/debian/prerm"
        "${CMAKE_SOURCE_DIR}/packaging/debian/postrm")
endif()

# Custom target for building Debian package using native tools
add_custom_target(deb-package
    COMMAND dpkg-buildpackage -us -uc -b
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building Debian package using dpkg-buildpackage"
) 