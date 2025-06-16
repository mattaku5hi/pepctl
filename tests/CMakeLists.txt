# Find test dependencies - try modern CMake approach first
find_package(GTest REQUIRED)

# Include test utilities
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Test executable
add_executable(pepctl_tests
    test_core.cpp
    test_policy_engine.cpp
    test_logger.cpp
    test_metrics.cpp
    test_utils.cpp
)

target_link_libraries(pepctl_tests
    pepctl_core
    pepctl_policy
    pepctl_logger
    pepctl_metrics
    GTest::gtest_main
    GTest::gtest
    ${Boost_LIBRARIES}
    ${FMT_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    Threads::Threads
)

# Add include directories for fmt and spdlog
target_include_directories(pepctl_tests PRIVATE
    ${FMT_INCLUDE_DIRS}
    ${SPDLOG_INCLUDE_DIRS}
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(pepctl_tests)

# Integration tests
add_subdirectory(integration)
