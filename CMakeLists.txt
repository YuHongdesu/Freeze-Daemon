cmake_minimum_required(VERSION 3.22)
project(freeze_daemon CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 全局优化
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

add_compile_options(-Wall -Wextra -O2 -ffunction-sections -fdata-sections)

# === eBPF 编译 ===
add_custom_target(bpf
    COMMAND clang -target bpf -O2 -g -mcpu=v2
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

# 链接选项
target_link_options(freeze_daemon PRIVATE -Wl,--gc-sections -Wl,--strip-all -s)

# libbpf
find_library(LIBBPF_STATIC NAMES libbpf.a HINTS ${CMAKE_SOURCE_DIR}/prebuilt/libbpf)
find_path(LIBBPF_INCLUDE NAMES bpf/libbpf.h HINTS ${CMAKE_SOURCE_DIR}/prebuilt/libbpf/include)

target_include_directories(freeze_daemon PRIVATE ${LIBBPF_INCLUDE})
target_link_libraries(freeze_daemon ${LIBBPF_STATIC} pthread elf z)

message(STATUS "freeze_daemon configured. libbpf: ${LIBBPF_STATIC}")
