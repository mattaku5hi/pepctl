# PEPCTL Test Suites Documentation

This document provides a comprehensive overview of the test suites implemented for the PEPCTL eBPF Network Security Framework.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Unit Tests](#unit-tests)
- [Integration Tests](#integration-tests)
- [Test Coverage Areas](#test-coverage-areas)
- [Running Tests](#running-tests)
- [Test Utilities](#test-utilities)
- [Future Test Requirements](#future-test-requirements)

## Overview

The PEPCTL project implements a comprehensive testing strategy with multiple layers:

1. **Unit Tests** - Testing individual components in isolation
2. **Integration Tests** - Testing component interactions and full system behavior
3. **Performance Tests** - Validating system performance under load
4. **End-to-End Tests** - Testing complete workflows with real network clients

## Test Structure

```
tests/
├── CMakeLists.txt              # Main test configuration
├── test_utils.h                # Common test utilities and helpers
├── test_utils.cpp              # Test utility implementations
├── test_core.cpp               # Core functionality tests
├── test_policy_engine.cpp      # Policy engine unit tests
├── test_logger.cpp             # Logging system tests
├── test_metrics.cpp            # Metrics server tests
└── integration/                # Integration test suite
    ├── CMakeLists.txt          # Integration test configuration
    ├── integration_test.cpp    # Core integration tests
    ├── test_client.cpp         # HTTP test client for API testing
    └── run_tests.sh            # Comprehensive test runner script
```

## Unit Tests

### Core Component Tests (`test_core.cpp`)

**Purpose**: Validates basic core functionality and data structures.

**Coverage**:
- Core data structure initialization
- Network address parsing and conversion
- Protocol enumeration handling
- Basic utility functions
- Memory management patterns

**Key Test Cases**:
- IP address string to uint32_t conversion
- Protocol parsing (TCP, UDP, ICMP, ANY)
- PacketInfo structure validation
- Error handling for invalid inputs

### Policy Engine Tests (`test_policy_engine.cpp`)

**Purpose**: Comprehensive testing of the policy management system.

**Coverage**:
- Policy creation, update, and deletion
- Policy lookup and matching algorithms
- JSON policy parsing and serialization
- Rate limiting functionality
- Thread-safe operations
- Policy expiration handling

**Key Test Cases**:
- Policy CRUD operations
- Wildcard policy matching
- Rate limit enforcement
- Concurrent policy access
- Policy file loading/saving
- Cache invalidation

### Logger Tests (`test_logger.cpp`)

**Purpose**: Validates logging system functionality and integration.

**Coverage**:
- Log level filtering
- Structured logging with contexts
- File and systemd journal output
- Thread-safe logging operations
- Log rotation handling

**Key Test Cases**:
- Multi-level logging (debug, info, warn, error)
- LogContext field addition
- Concurrent logging from multiple threads
- Log file creation and rotation
- Systemd journal integration

### Metrics Server Tests (`test_metrics.cpp`)

**Purpose**: Tests HTTP metrics server and Prometheus integration.

**Coverage**:
- HTTP server initialization and shutdown
- Metrics registration and updates
- Prometheus format output
- REST API endpoints
- Background metrics collection

**Key Test Cases**:
- Metrics server startup/shutdown
- Counter and gauge metric updates
- HTTP endpoint responses
- Concurrent client handling
- Metrics aggregation

## Integration Tests

### System Integration Tests (`integration_test.cpp`)

**Purpose**: Validates complete system behavior with all components working together.

**Coverage**:
- Daemon startup and shutdown sequences
- Policy loading from configuration files
- HTTP API functionality
- System configuration management
- Error handling and recovery

**Key Test Cases**:

#### 1. Daemon Lifecycle Test
```cpp
TEST_F(IntegrationTest, DaemonStartupShutdownTest)
```
- Forks pepctl daemon process
- Validates PID file creation
- Tests graceful shutdown with SIGTERM
- Verifies cleanup of system resources

#### 2. Policy Loading Test
```cpp
TEST_F(IntegrationTest, PolicyLoadingTest)
```
- Creates test policy files
- Starts daemon with policy configuration
- Validates policies are loaded via metrics endpoint
- Checks policy count in metrics output

#### 3. Metrics Endpoint Test
```cpp
TEST_F(IntegrationTest, MetricsEndpointTest)
```
- Tests `/health` endpoint availability
- Validates `/metrics` Prometheus format output
- Checks `/policies` endpoint responses

#### 4. Policy Management API Test
```cpp
TEST_F(IntegrationTest, PolicyManagementAPITest)
```
- Tests REST API for policy management
- Validates POST requests for policy creation
- Tests GET requests for policy retrieval
- Tests DELETE requests for policy removal

### HTTP Test Client (`test_client.cpp`)

**Purpose**: Provides a dedicated HTTP client for testing API endpoints.

**Features**:
- Command-line interface for endpoint testing
- Support for all HTTP methods (GET, POST, DELETE)
- JSON request body support
- Automated test suite execution

**Available Tests**:
- Health endpoint testing
- Metrics endpoint validation
- Policy CRUD operations
- Statistics endpoint testing

**Usage**:
```bash
# Run all tests
./pepctl_test_client --all --host 127.0.0.1 --port 8080

# Test specific endpoint
./pepctl_test_client --endpoint /health --method GET

# Test policy creation
./pepctl_test_client --endpoint /api/policies --method POST --body '{"id":"test","action":"ALLOW"}'
```

### Integration Test Runner (`run_tests.sh`)

**Purpose**: Comprehensive test automation script for full system validation.

**Features**:
- Automated environment setup
- Daemon lifecycle management
- Sequential test execution
- Cleanup and error handling
- Root privilege validation for eBPF operations

**Test Sequence**:
1. **Environment Setup**
   - Creates test configuration files
   - Sets up temporary directories
   - Validates required binaries

2. **Daemon Testing**
   - Starts pepctl daemon in test mode
   - Validates process startup
   - Tests configuration loading

3. **API Testing**
   - Health endpoint validation
   - Metrics collection testing
   - Policy management operations

4. **Cleanup**
   - Graceful daemon shutdown
   - Temporary file cleanup
   - Resource deallocation

## Test Coverage Areas

### ✅ Currently Covered

1. **Core Functionality**
   - Data structure validation
   - Network address handling
   - Protocol parsing

2. **Policy Engine**
   - Policy CRUD operations
   - JSON serialization/deserialization
   - Thread-safe access patterns
   - Rate limiting logic

3. **Logging System**
   - Multi-level logging
   - Structured contexts
   - Thread safety

4. **Metrics Server**
   - HTTP server functionality
   - Prometheus format output
   - REST API endpoints

5. **Integration Testing**
   - Daemon lifecycle management
   - Configuration loading
   - API endpoint validation

### ❌ Missing Coverage (Areas for Improvement)

1. **eBPF Integration**
   - eBPF program loading and attachment
   - Kernel-userspace communication
   - eBPF map operations
   - Performance under packet load

2. **Real Network Traffic Testing**
   - Live packet processing
   - Policy enforcement validation
   - Performance benchmarking
   - Network interface interaction

3. **End-to-End Client-Server Scenarios**
   - Multiple clients connecting to protected servers
   - Policy enforcement verification
   - Rate limiting validation
   - Blocking/allowing traffic verification

4. **Error Recovery Testing**
   - System failure scenarios
   - Network interface failures
   - Configuration reload testing
   - Memory pressure testing

5. **Performance Testing**
   - High-throughput packet processing
   - Concurrent client handling
   - Memory usage under load
   - CPU utilization benchmarks

## Running Tests

### Prerequisites

```bash
# Install test dependencies
sudo apt-get install googletest-dev

# Build project with tests enabled
cd build
cmake .. -DENABLE_TESTS=ON
make -j$(nproc)
```

### Unit Tests

```bash
# Run all unit tests
cd build
ctest --verbose

# Run specific test suite
./tests/pepctl_tests --gtest_filter="PolicyEngineTest.*"

# Generate test report
./tests/pepctl_tests --gtest_output=xml:test_results.xml
```

### Integration Tests

```bash
# Run integration tests (requires root for eBPF)
cd build
sudo ./tests/integration/run_tests.sh

# Run specific integration test
sudo ./tests/integration/pepctl_integration_tests --gtest_filter="IntegrationTest.DaemonStartupShutdownTest"

# Run HTTP client tests
./tests/integration/pepctl_test_client --all --host 127.0.0.1 --port 8080
```

### Test Automation

```bash
# Run complete test suite
make test

# Run tests with coverage report
make test_coverage

# Run performance benchmarks
make benchmark
```

## Test Utilities

### TestConfig Structure
```cpp
struct TestConfig {
    std::string pid_file;
    std::string log_file;
    std::string ebpf_program_path;
    std::string interface;
    uint16_t metrics_port;
    bool metrics_enabled;
};
```

### Key Utility Functions

- `generate_test_packet()` - Creates test PacketInfo structures
- `generate_test_traffic()` - Creates bulk test traffic
- `wait_for_condition()` - Waits for asynchronous conditions
- `make_http_request()` - HTTP client for API testing
- `create_test_config_file()` - Generates test configurations

## Future Test Requirements

### 1. End-to-End Network Testing

**Need**: Real client-server scenarios with policy enforcement validation.

**Implementation Plan**:
```bash
# Proposed test scenario
tests/e2e/
├── test_network_scenario.cpp
├── mock_server.cpp
├── mock_client.cpp
└── policy_validation.cpp
```

**Test Cases**:
- Client attempts to connect to server on allowed port → SUCCESS
- Client attempts to connect to server on blocked port → BLOCKED
- Rate-limited client exceeds threshold → RATE LIMITED
- Multiple clients with different policies → POLICY-SPECIFIC BEHAVIOR

### 2. eBPF Performance Testing

**Need**: Validate eBPF program performance under realistic network loads.

**Implementation Plan**:
- Packet generation tools
- Performance measurement frameworks
- Memory usage monitoring
- CPU utilization tracking

### 3. Failure Recovery Testing

**Need**: Validate system behavior under various failure conditions.

**Test Scenarios**:
- Network interface down/up cycles
- eBPF program reload scenarios
- Configuration file corruption
- Memory exhaustion conditions

### 4. Load Testing

**Need**: Validate system behavior under high concurrent load.

**Metrics to Track**:
- Packets per second throughput
- Concurrent client connections
- Memory usage patterns
- Response time distributions

## Conclusion

The current test suite provides solid coverage for core functionality, policy management, and basic integration scenarios. However, there are significant opportunities for improvement in areas of eBPF integration, real network traffic testing, and end-to-end client-server validation.

The missing **real client-server testing scenarios** represent the most critical gap in our current test coverage. These tests would validate that the PEPCTL system actually enforces policies correctly when real clients attempt to connect to real servers through the eBPF-protected network interface.

**Priority Test Development Areas**:
1. End-to-end client-server scenarios
2. eBPF program integration testing  
3. Performance and load testing
4. Failure recovery validation

This comprehensive test suite ensures the reliability, performance, and correctness of the PEPCTL eBPF Network Security Framework. 