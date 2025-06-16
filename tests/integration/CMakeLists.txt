# Integration test utilities
add_executable(pepctl_integration_test
    integration_test.cpp
    ../test_utils.cpp
)

target_link_libraries(pepctl_integration_test
    pepctl_core
    pepctl_policy
    pepctl_ebpf
    pepctl_metrics
    pepctl_logger
    GTest::gtest_main
    GTest::gtest
    ${Boost_LIBRARIES}
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${FMT_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    Threads::Threads
)

# Add include directories for fmt and spdlog
target_include_directories(pepctl_integration_test PRIVATE
    ${FMT_INCLUDE_DIRS}
    ${SPDLOG_INCLUDE_DIRS}
)

# Test client for HTTP API testing
add_executable(pepctl_test_client
    test_client.cpp
)

target_link_libraries(pepctl_test_client
    ${Boost_LIBRARIES}
    Threads::Threads
)

# Install test utilities
install(TARGETS pepctl_integration_test pepctl_test_client
        DESTINATION bin/test)

# Copy test scripts
install(FILES
    run_tests.sh
    test_policies.json
    DESTINATION share/pepctl/tests
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
) 