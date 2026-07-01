cmake_minimum_required(VERSION 3.22)
project(freeze_daemon CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

add_compile_options(-Wall -Wextra -O2 -ffunction-sections -fdata-sections)

set(LIBBPF_DIR "${CMAKE_SOURCE_DIR}/prebuilt/libbpf" CACHE PATH "Path to libbpf installation")

add_custom_target(bpf
    COMMAND clang -target bpf -O2 -g -mcpu=v2
            -D__TARGET_ARCH_arm64
            -I${CMAKE_SOURCE_DIR}/src
            -c ${CMAKE_SOURCE_DIR}/src/platform/freeze_monitor.bpf.c
            -o ${CMAKE_BINARY_DIR}/freeze_monitor.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/src/platform/freeze_monitor.bpf.c
            ${CMAKE_SOURCE_DIR}/src/vmlinux.h
    COMMENT "Building eBPF program"
)

add_executable(freeze_daemon src/main.cpp)
add_dependencies(freeze_daemon bpf)

target_include_directories(freeze_daemon PRIVATE src)

target_link_options(freeze_daemon PRIVATE -Wl,--gc-sections -Wl,--strip-all -s)

set(LIBBPF_LIB "${LIBBPF_DIR}/lib/libbpf.a")
set(LIBBPF_INCLUDE "${LIBBPF_DIR}/include")

if(NOT EXISTS "${LIBBPF_LIB}" OR NOT EXISTS "${LIBBPF_INCLUDE}/bpf/libbpf.h")
    message(FATAL_ERROR "libbpf not found at ${LIBBPF_DIR}. "
                        "Expected ${LIBBPF_LIB} and ${LIBBPF_INCLUDE}/bpf/libbpf.h")
endif()

target_include_directories(freeze_daemon PRIVATE ${LIBBPF_INCLUDE})
target_link_libraries(freeze_daemon ${LIBBPF_LIB})

message(STATUS "freeze_daemon configured. libbpf: ${LIBBPF_LIB}")