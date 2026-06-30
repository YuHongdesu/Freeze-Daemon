#pragma once
#include <string>
#include <cstdio>
#include "util/logger.h"

// 平台层：前台 app 检测的 shell 兜底方案
//
// 借鉴 Frosty frosty.sh 的 get_fg_pkg()：用 dumpsys 查询当前前台包名，
// 两层 fallback（先查 Activity 层，再查 Window 层），不依赖 eBPF。
//
// 用途：我们的主路径是 eBPF 的 top_app_cgroup_id 机制（毫秒级、零轮询），
// 但 BpfLoader::refresh_top_app_cgroup() 在某些场景可能连续失败
// （cgroup.id 文件读取失败、内核不支持等），这种情况下前后台检测会
// 完全失效。这个函数作为低频兜底（不是主路径，不追求性能），
// 在 eBPF 连续失败达到阈值时被动态调用一次，确保系统至少还能
// 感知到前台 app 是谁，避免冻结策略完全失明。
namespace ForegroundFallback {

constexpr const char* TAG = "FgFallback";

// 从形如 "...{abc123 0 com.example.app/.MainActivity}..." 的行中提取包名
// 定位 '/' 字符，向前回溯到上一个空格，中间即为包名
inline std::string parse_pkg_from_line(const std::string& line) {
    auto slash_pos = line.find('/');
    if (slash_pos == std::string::npos) return "";

    auto space_pos = line.rfind(' ', slash_pos);
    if (space_pos == std::string::npos) return "";

    std::string pkg = line.substr(space_pos + 1, slash_pos - space_pos - 1);
    // 过滤掉明显不是包名的解析结果（必须含点号，且不含花括号残留）
    if (pkg.find('.') == std::string::npos) return "";
    if (pkg.find('{') != std::string::npos) return "";
    return pkg;
}

// 两种 dumpsys 输出共享相同的 "{hex userId pkg/activity}" 结构，
// 用同一套解析逻辑处理，避免重复实现
inline std::string extract_pkg_from_dumpsys(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";

    char buf[512] = {};
    bool ok = fgets(buf, sizeof(buf), pipe) != nullptr;
    pclose(pipe);
    if (!ok) return "";

    return parse_pkg_from_line(buf);
}

// 第一层：从 Activity 管理器查询当前 resumed activity 所属包名
// 格式: "mResumedActivity: ActivityRecord{hex token userId pkg/activity ...}"
inline std::string query_via_activity() {
    const char* cmd =
        "dumpsys activity activities 2>/dev/null | "
        "grep -m1 'mResumedActivity\\|topResumedActivity'";
    return extract_pkg_from_dumpsys(cmd);
}

// 第二层：从 WindowManager 查询当前聚焦窗口所属包名（Activity 层查询失败时的兜底）
// 格式: "mCurrentFocus: Window{hex userId pkg/activity}" — 结构与上面相同
inline std::string query_via_window() {
    const char* cmd =
        "dumpsys window windows 2>/dev/null | "
        "grep -m1 'mCurrentFocus\\|mFocusedWindow'";
    return extract_pkg_from_dumpsys(cmd);
}

// 对外唯一入口：两层 fallback，第一层失败才尝试第二层
inline std::string detect_foreground_package() {
    std::string pkg = query_via_activity();
    if (!pkg.empty()) return pkg;

    pkg = query_via_window();
    if (!pkg.empty()) {
        LOG_I(TAG, "Activity层查询失败，Window层兜底成功: " + pkg);
        return pkg;
    }

    LOG_W(TAG, "前台包名检测完全失败（两层 fallback 均未命中）");
    return "";
}

} // namespace ForegroundFallback
