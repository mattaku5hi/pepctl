# eBPF Programs CMake Configuration

cmake_minimum_required(VERSION 3.20)

# Find required tools
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(CLANG_EXECUTABLE "${CMAKE_C_COMPILER}" CACHE FILEPATH "Clang executable to compile eBPF programs")
else()
    find_program(CLANG_EXECUTABLE clang)
    if(NOT CLANG_EXECUTABLE)
        message(FATAL_ERROR "clang not found. Install clang or configure the project with -DCMAKE_C_COMPILER=clang")
    endif()
endif()
find_program(BPFTOOL_EXECUTABLE bpftool)

# Architecture detection
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(ARCH STREQUAL "x86_64")
    set(CLANG_ARCH "x86")
    set(LINUX_ARCH "x86")
elseif(ARCH STREQUAL "aarch64")
    set(CLANG_ARCH "arm64")
    set(LINUX_ARCH "arm64")
else()
    set(CLANG_ARCH "${ARCH}")
    set(LINUX_ARCH "${ARCH}")
endif()

# Find kernel headers
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(KERNEL_HEADERS "/usr/src/linux-headers-${KERNEL_VERSION}")
if(NOT EXISTS "${KERNEL_HEADERS}")
    set(KERNEL_HEADERS "/lib/modules/${KERNEL_VERSION}/build")
endif()

if(NOT EXISTS "${KERNEL_HEADERS}")
    message(FATAL_ERROR "Kernel headers not found. Install linux-headers-${KERNEL_VERSION}")
endif()

# Get clang target triple for includes
execute_process(
    COMMAND ${CLANG_EXECUTABLE} -dumpmachine
    OUTPUT_VARIABLE CLANG_TARGET_TRIPLE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# eBPF compiler flags
set(EBPF_COMPILE_FLAGS
    -O2
    -target bpf
    -D__KERNEL__
    -D__BPF_TRACING__
    -D__BPF__
    -g
    -Wno-unused-value
    -Wno-pointer-sign
    -Wno-compare-distinct-pointer-types
    -Wno-gnu-variable-sized-type-not-at-end
    -Wno-address-of-packed-member
    -Wno-tautological-compare
    -Wno-unknown-warning-option
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -fno-unwind-tables
)

# eBPF include directories
set(EBPF_INCLUDE_DIRS
    -I${KERNEL_HEADERS}/include
    -I${KERNEL_HEADERS}/include/uapi
    -I${KERNEL_HEADERS}/arch/${LINUX_ARCH}/include
    -I${KERNEL_HEADERS}/arch/${LINUX_ARCH}/include/uapi
    -I${KERNEL_HEADERS}/arch/${LINUX_ARCH}/include/generated
    -I${KERNEL_HEADERS}/arch/${LINUX_ARCH}/include/generated/uapi
    -I/usr/include/${CLANG_TARGET_TRIPLE}
)

# Function to compile eBPF programs
function(add_ebpf_program TARGET_NAME SOURCE_FILE)
    get_filename_component(PROGRAM_NAME ${SOURCE_FILE} NAME_WE)
    set(OUTPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROGRAM_NAME}.o")
    
    add_custom_command(
        OUTPUT ${OUTPUT_FILE}
        COMMAND ${CLANG_EXECUTABLE}
            ${EBPF_COMPILE_FLAGS}
            ${EBPF_INCLUDE_DIRS}
            -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
            -o ${OUTPUT_FILE}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
        COMMENT "Compiling eBPF program: ${SOURCE_FILE}"
        VERBATIM
    )
    
    add_custom_target(${TARGET_NAME} ALL DEPENDS ${OUTPUT_FILE})
    
    # Set properties for easy access
    set_target_properties(${TARGET_NAME} PROPERTIES
        EBPF_OBJECT_FILE ${OUTPUT_FILE}
        EBPF_SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
    )
    
    # Add verification target if bpftool is available
    if(BPFTOOL_EXECUTABLE)
        add_custom_target(verify_${TARGET_NAME}
            COMMAND ${BPFTOOL_EXECUTABLE} prog load ${OUTPUT_FILE} /sys/fs/bpf/pepctl_verify_${PROGRAM_NAME} || exit 1
            COMMAND ${BPFTOOL_EXECUTABLE} prog del pinned /sys/fs/bpf/pepctl_verify_${PROGRAM_NAME} || true
            DEPENDS ${TARGET_NAME}
            COMMENT "Verifying eBPF program: ${PROGRAM_NAME}"
            VERBATIM
        )
    endif()
endfunction()

# Add eBPF programs
add_ebpf_program(packet_filter packet_filter.c)

# Create a combined target for all eBPF programs
add_custom_target(ebpf_programs ALL DEPENDS packet_filter)

# Verification target for all programs
if(BPFTOOL_EXECUTABLE)
    add_custom_target(verify_ebpf DEPENDS verify_packet_filter)
endif()

# Installation
install(FILES 
    ${CMAKE_CURRENT_BINARY_DIR}/packet_filter.o
    DESTINATION usr/share/pepctl/ebpf
    COMPONENT ebpf
)

# Debug information target
add_custom_target(ebpf_debug
    COMMAND ${CMAKE_COMMAND} -E echo "CLANG: ${CLANG_EXECUTABLE}"
    COMMAND ${CMAKE_COMMAND} -E echo "ARCH: ${ARCH}"
    COMMAND ${CMAKE_COMMAND} -E echo "CLANG_ARCH: ${CLANG_ARCH}"
    COMMAND ${CMAKE_COMMAND} -E echo "LINUX_ARCH: ${LINUX_ARCH}"
    COMMAND ${CMAKE_COMMAND} -E echo "KERNEL_HEADERS: ${KERNEL_HEADERS}"
    COMMAND ${CMAKE_COMMAND} -E echo "KERNEL_VERSION: ${KERNEL_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "CLANG_TARGET_TRIPLE: ${CLANG_TARGET_TRIPLE}"
    COMMENT "Showing eBPF build configuration"
)

# Export variables for parent CMake
set(EBPF_OBJECT_FILES 
    "${CMAKE_CURRENT_BINARY_DIR}/packet_filter.o"
    PARENT_SCOPE
) 