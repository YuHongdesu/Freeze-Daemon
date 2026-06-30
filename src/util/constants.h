#pragma once
#include <cstdint>

// ── 路径 ─────────────────────────────────────────────────────
namespace Path {
    constexpr const char* CONFIG_FILE    = "/data/adb/modules/freeze-daemon/config/freeze.conf";
    constexpr const char* USER_WHITELIST = "/data/adb/modules/freeze-daemon/config/user_whitelist.txt";
    constexpr const char* SYS_BLACKLIST  = "/data/adb/modules/freeze-daemon/config/system_blacklist.txt";
    constexpr const char* CGROUP_ROOT    = "/sys/fs/cgroup/freeze_daemon";
    constexpr const char* CGROUP_FROZEN  = "/sys/fs/cgroup/freeze_daemon/frozen";
    constexpr const char* CGROUP_ACTIVE  = "/sys/fs/cgroup/freeze_daemon/active";
    constexpr const char* PID_FILE       = "/data/adb/modules/freeze-daemon/daemon.pid";
    constexpr const char* LOG_FILE       = "/data/adb/modules/freeze-daemon/logs/daemon.log";
    constexpr const char* DEEP_SLEEP_LOCK = "/data/adb/modules/freeze-daemon/deep_sleep.lock";
}

// ── 默认配置值 ───────────────────────────────────────────────
namespace Default {
    constexpr int  BG_FREEZE_DELAY_MS    = 5000;
    constexpr int  SCREEN_OFF_DELAY_MS   = 3000;
    constexpr int  BOUNCE_LIMIT          = 2;      // 关闭系统 Freezer 后理论上不该再 bounce，调低更快退避
    constexpr int  BOUNCE_BACKOFF_MS     = 15000;  // 退避时间相应延长，减少反复对抗
    constexpr bool COMPACTION_ON         = true;   // 内存压缩与 Freezer 无关，保留
    constexpr bool WIFI_SCAN_OFF         = false;
    constexpr int  DEEP_SLEEP_DELAY_MS   = 30000;
    constexpr bool DEEP_SLEEP_ON         = false;
    constexpr bool USER_APPOP_RESTRICT   = true;
}

// ── eBPF 事件类型（必须与 freeze_monitor.bpf.c 完全一致）──────
namespace BpfEvent {
    constexpr uint8_t APP_FOREGROUND = 1;
    constexpr uint8_t APP_BACKGROUND = 2;
    constexpr uint8_t SCREEN_ON      = 3;
    constexpr uint8_t SCREEN_OFF     = 4;
    constexpr uint8_t SYS_UNFREEZE   = 5;
    constexpr uint8_t PROC_DIED      = 6;
}

// AppOp 权限剥夺列表的唯一数据源是 config/appop_restrict_list.txt，
// 由 service.sh 和 appop_manager.h 共同读取，不再在此处硬编码常量字符串
// （此前的 AppOp namespace 已无任何代码引用，属死代码，已移除）

// ── top-app cgroup 路径（Android 标准路径）────────────────────
namespace CgroupPath {
    // Android 系统的 top-app cgroup（前台 app 所在）
    constexpr const char* TOP_APP = "/sys/fs/cgroup/top-app";
}
