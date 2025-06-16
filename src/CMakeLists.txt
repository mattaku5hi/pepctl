# Utilities library (utility functions only - no dependencies on other pepctl libraries)
add_library(pepctl_utils SHARED
    utils.cpp
)

target_link_libraries(pepctl_utils
    ${Boost_LIBRARIES}
    Threads::Threads
)

# Logger library (depends on utils for NetworkAddress::toString)
add_library(pepctl_logger SHARED
    logger.cpp
)

target_link_libraries(pepctl_logger
    pepctl_utils
    ${SPDLOG_LIBRARIES}
    ${FMT_LIBRARIES}
    ${LIBSYSTEMD_LIBRARIES}
    Threads::Threads
)

# Add include directories for pkg-config dependencies
target_include_directories(pepctl_logger PRIVATE 
    ${SPDLOG_INCLUDE_DIRS}
    ${FMT_INCLUDE_DIRS}
    ${LIBSYSTEMD_INCLUDE_DIRS}
)

# Add nlohmann_json dependency
if(nlohmann_json_FOUND)
    target_link_libraries(pepctl_logger nlohmann_json::nlohmann_json)
elseif(NLOHMANN_JSON_FOUND)
    target_link_libraries(pepctl_logger ${NLOHMANN_JSON_LIBRARIES})
    target_include_directories(pepctl_logger PRIVATE ${NLOHMANN_JSON_INCLUDE_DIRS})
endif()

# eBPF manager library (depends on logger)
add_library(pepctl_ebpf SHARED
    ebpf_manager.cpp
)

target_link_libraries(pepctl_ebpf
    pepctl_logger
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${Boost_LIBRARIES}
    Threads::Threads
)

# Policy engine library (depends on utils for utility functions and logger)
add_library(pepctl_policy SHARED
    policy_engine.cpp
)

target_link_libraries(pepctl_policy
    pepctl_utils
    pepctl_logger
    ${Boost_LIBRARIES}
    Threads::Threads
)

# Add nlohmann_json dependency for policy engine
if(nlohmann_json_FOUND)
    target_link_libraries(pepctl_policy nlohmann_json::nlohmann_json)
elseif(NLOHMANN_JSON_FOUND)
    target_link_libraries(pepctl_policy ${NLOHMANN_JSON_LIBRARIES})
    target_include_directories(pepctl_policy PRIVATE ${NLOHMANN_JSON_INCLUDE_DIRS})
endif()

# Metrics server library (depends on policy and ebpf)
add_library(pepctl_metrics SHARED
    metrics_server.cpp
)

target_link_libraries(pepctl_metrics
    pepctl_logger
    pepctl_policy
    pepctl_ebpf
    ${Boost_LIBRARIES}
    Threads::Threads
)

# Daemon library (orchestrates all components - depends on everything)
add_library(pepctl_core SHARED
    core.cpp
)

target_link_libraries(pepctl_core
    pepctl_utils
    pepctl_logger
    pepctl_policy
    pepctl_ebpf
    pepctl_metrics
    ${Boost_LIBRARIES}
    Threads::Threads
)

# Main pepctl executable
add_executable(pepctl main.cpp)

target_link_libraries(pepctl PRIVATE
    pepctl_core
    pepctl_policy
    pepctl_ebpf
    pepctl_metrics
    pepctl_logger
    pepctl_utils
    ${Boost_LIBRARIES}
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    ${FMT_LIBRARIES}
    ${LIBSYSTEMD_LIBRARIES}
    Threads::Threads
)

# Add systemd include directories
target_include_directories(pepctl PRIVATE ${LIBSYSTEMD_INCLUDE_DIRS})

# Add nlohmann_json dependency for main executable
if(nlohmann_json_FOUND)
    target_link_libraries(pepctl PRIVATE nlohmann_json::nlohmann_json)
elseif(NLOHMANN_JSON_FOUND)
    target_link_libraries(pepctl PRIVATE ${NLOHMANN_JSON_LIBRARIES})
    target_include_directories(pepctl PRIVATE ${NLOHMANN_JSON_INCLUDE_DIRS})
endif()

# Add eBPF dependency
add_dependencies(pepctl ebpf_programs)

# Install executable
install(TARGETS pepctl DESTINATION /usr/bin/)

# Install libraries
install(TARGETS 
    pepctl_core 
    pepctl_policy 
    pepctl_ebpf 
    pepctl_metrics 
    pepctl_logger
    pepctl_utils
    DESTINATION lib
) 