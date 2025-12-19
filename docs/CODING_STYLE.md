# PEPCTL Coding Style Guide

This document outlines the coding standards and conventions used in the PEPCTL project.

## Overview

The PEPCTL project follows a **Mozilla-based style** with modern C++20 enhancements and specific customizations for network programming and eBPF integration.

## Automatic Formatting

### Tools Used
- **clang-format 18+** for automatic code formatting
- **EditorConfig** for consistent editor settings
- **Git pre-commit hooks** for enforcing style

### Usage

#### Format entire codebase:
```bash
./scripts/format-code.sh
```

#### Format specific file:
```bash
clang-format -i src/logger.cpp
```

#### Check formatting (dry run):
```bash
clang-format --dry-run --Werror src/logger.cpp
```

## Naming Conventions

### Classes and Types
```cpp
class PolicyEngine          // PascalCase
struct PacketInfo           // PascalCase
enum class LogLevel         // PascalCase
using PolicyMap = std::map<std::string, Policy>;  // PascalCase
```

### Functions and Variables
```cpp
void evaluate_packet()      // snake_case
bool is_valid()            // snake_case
int packet_count = 0;      // snake_case
```

### Member Variables
```cpp
class Logger {
private:
    std::string m_log_file;     // m_ prefix for member variables
    LogLevel m_current_level;   // m_ prefix for member variables
    bool m_initialized;         // m_ prefix for member variables
};
```

### Constants and Macros
```cpp
const int MAX_PACKET_SIZE = 1500;           // UPPER_CASE
#define PEPCTL_VERSION_MAJOR 1              // UPPER_CASE
static constexpr uint32_t DEFAULT_TIMEOUT = 5000;  // UPPER_CASE
```

### Namespaces
```cpp
namespace pepctl {          // snake_case
namespace detail {          // snake_case
```

## Code Layout

### Indentation
- **4 spaces** for C++ code
- **2 spaces** for CMake and YAML files
- **No tabs** (spaces only)

### Line Length
- **100 characters maximum** per line
- Break long function parameters across multiple lines

### Braces
```cpp
// Classes, functions, control structures - braces on new line
class PolicyEngine
{
public:
    bool initialize()
    {
        if (condition)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
};

// Namespaces - opening brace on same line
namespace pepctl {

} // namespace pepctl
```

### Include Organization
```cpp
// 1. Main header (for .cpp files)
#include "pepctl/logger.h"

// 2. Project headers
#include "pepctl/core.h"
#include "pepctl/policy_engine.h"

// 3. External library headers
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

// 4. System C++ headers
#include <iostream>
#include <memory>
#include <string>

// 5. System C headers
#include <unistd.h>
```

### Function Parameters
```cpp
// Short parameter lists - single line
bool add_policy(const Policy& policy);

// Long parameter lists - multi-line with aligned parameters
void log_security_event(const std::string& event_type,
                        const std::string& client_ip,
                        const std::string& details,
                        LogLevel level = LogLevel::WARN);
```

### Constructor Initialization
```cpp
Logger::Logger()
    : m_current_level(LogLevel::INFO)
    , m_main_logger(nullptr)
    , m_structured_logger(nullptr)
{
    // Constructor body
}
```

## C++ Best Practices

### Modern C++ Features (C++20)
- Use `auto` when type is obvious
- Prefer `std::make_unique/std::make_shared`
- Use range-based for loops
- Utilize `constexpr` and `const` appropriately
- Leverage concepts where applicable

```cpp
// Good
auto policy = std::make_unique<Policy>();
for (const auto& entry : policy_map) {
    // process entry
}

// Avoid
Policy* policy = new Policy();  // Use smart pointers instead
```

### Error Handling
```cpp
// Use exceptions for exceptional circumstances
// Use std::optional for optional return values
std::optional<Policy> find_policy(const std::string& id) const;

// Use proper RAII
class PolicyEngine {
public:
    ~PolicyEngine() {
        shutdown();  // Automatic cleanup
    }
};
```

### Memory Management
- **RAII** for all resource management
- **Smart pointers** instead of raw pointers
- **Stack allocation** preferred over heap when possible

```cpp
// Good
std::unique_ptr<Logger> logger = std::make_unique<Logger>();
std::shared_ptr<Policy> policy = std::make_shared<Policy>();

// Avoid
Logger* logger = new Logger();  // Manual memory management
```

## Documentation

### Header Comments
```cpp
/**
 * @file logger.h
 * @brief High-performance logging system for PEPCTL
 * @author PEPCTL Team
 */
```

### Class Documentation
```cpp
/**
 * @brief Thread-safe policy engine for packet filtering
 * 
 * This class provides high-performance policy evaluation using
 * lock-free data structures and RCU-like semantics.
 */
class PolicyEngine {
    // ...
};
```

### Function Documentation
```cpp
/**
 * @brief Evaluate a packet against current policies
 * @param packet The packet information to evaluate
 * @return Policy evaluation result including action and metadata
 */
PolicyEvaluationResult evaluate_packet(const PacketInfo& packet);
```

## File Organization

### Header Files (.h)
```cpp
#pragma once

// Includes
#include "core.h"
#include <memory>

namespace pepctl {

// Forward declarations
class PolicyEngine;

// Class declaration
class Logger {
public:
    // Public interface

private:
    // Private members with m_ prefix
    std::string m_log_file;
};

} // namespace pepctl
```

### Source Files (.cpp)
```cpp
#include "pepctl/logger.h"

// Other includes...

namespace pepctl {

// Implementation
Logger::Logger()
    : m_log_file("/var/log/pepctl.log")
{
    // Constructor
}

} // namespace pepctl
```

## Git Integration

### Pre-commit Hook
The project automatically checks code formatting before commits:
```bash
# The pre-commit hook will reject commits with formatting issues
git commit -m "Add new feature"
# If formatting issues exist, fix them:
./scripts/format-code.sh
git add .
git commit -m "Add new feature"
```

### Editor Integration
Most modern editors support clang-format and EditorConfig:
- **VS Code**: Install C++ and EditorConfig extensions
- **CLion**: Built-in support for both
- **Vim**: Use vim-clang-format plugin
- **Emacs**: Use clang-format package

## Platform Considerations

### Linux-Specific Code
```cpp
#ifdef __linux__
    // Linux-specific implementation
#endif
```

### eBPF Integration
- Use proper alignment for kernel structures
- Follow eBPF naming conventions for maps and programs
- Maintain compatibility with different kernel versions

### Network Programming
- Use network byte order for protocol fields
- Handle endianness correctly
- Validate all network input

## Performance Guidelines

### Memory Allocation
- Minimize dynamic allocations in hot paths
- Use object pools for frequently allocated objects
- Prefer stack allocation when possible

### Concurrency
- Use lock-free algorithms where appropriate
- Minimize lock contention
- Prefer shared_mutex for read-heavy workloads

### eBPF Performance
- Keep eBPF programs minimal and efficient
- Use appropriate map types for data access patterns
- Profile and optimize hot code paths

## Examples

See the existing codebase for examples of proper style implementation:
- `src/logger.cpp` - Logging implementation
- `src/policy_engine.cpp` - Policy management
- `include/pepctl/core.h` - Core data structures

## Style Enforcement

The project uses automated tools to enforce coding style:
1. **clang-format** for code formatting
2. **Git pre-commit hooks** for commit-time checking
3. **CI/CD pipeline** for continuous validation

To maintain consistency, all contributors must:
1. Use the provided `.clang-format` configuration
2. Run formatting scripts before committing
3. Follow the naming and documentation conventions
4. Write code that passes all style checks 