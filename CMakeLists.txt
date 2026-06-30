cmake_minimum_required(VERSION 3.22)
project(freeze_daemon CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── 1. 全局 LTO (链接时优化) ──────────────────────────────
# 跨源文件进行全局内联和死代码剔除，能动性强，收益极高
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

# ── 2. 编译选项 (平衡性能与体积) ─────────────────────────
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    
    # 保持 -O2 性能优先，后台核心逻辑响应更灵敏
    -O2 
    
    # 将各个函数和变量独立分段，为后续的垃圾回收(gc-sections)做准备
    -ffunction-sections
    -fdata-sections
)

# ── 3. 源文件与目标 ───────────────────────────────────────
add_executable(freeze_daemon src/main.cpp)
target_include_directories(freeze_daemon PRIVATE src)

# ── 4. 链接选项 (Grok 推荐双保险剥离) ─────────────────────
target_link_options(freeze_daemon PRIVATE
    # 垃圾回收机制：配合分段编译，剔除所有未被实际调用的死代码
    -Wl,--gc-sections
    # 剥离调试符号表，减小二进制体积，降低 I/O 载入开销
    -Wl,--strip-all
    # NDK 交叉编译双保险：确保符号和调试信息被彻底抹除
    -s
)

# ── 5. libbpf 静态链接 ────────────────────────────────────
find_library(LIBBPF_STATIC
    NAMES libbpf.a
    HINTS
        ${CMAKE_SOURCE_DIR}/prebuilt/libbpf   # NDK 交叉编译时放这里
        /usr/lib/x86_64-linux-gnu             # Ubuntu apt 安装路径
        /usr/local/lib
)

if(NOT LIBBPF_STATIC)
    message(FATAL_ERROR
        "libbpf static library not found.\n"
        "For cross-compile: place arm64 libbpf.a in prebuilt/libbpf/\n"
        "For host build: sudo apt install libbpf-dev")
endif()

find_path(LIBBPF_INCLUDE
    NAMES bpf/libbpf.h
    HINTS
        ${CMAKE_SOURCE_DIR}/prebuilt/libbpf/include
        /usr/include
)

target_include_directories(freeze_daemon PRIVATE ${LIBBPF_INCLUDE})
target_link_libraries(freeze_daemon
    ${LIBBPF_STATIC}
    pthread
    elf      
    z        
)

message(STATUS "freeze_daemon configured. libbpf: ${LIBBPF_STATIC}")
