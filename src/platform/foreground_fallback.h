#pragma once
#include <string>
#include <cstdio>
#include "util/logger.h"

// 纯 shell fallback 前台包名检测，不依赖任何 cgroup 或 eBPF
namespace ForegroundFallback {

constexpr const char* TAG = "FgFallback";

// 从 "ACTIVITY com.example.app/.MainActivity ..." 行提取包名
inline std::string parse_from_top_output(const std::string& line) {
    auto pos = line.find("ACTIVITY ");
    if (pos == std::string::npos) return "";
    pos += 9; // 跳过 "ACTIVITY "
    auto end = line.find(' ', pos);
    std::string pkg_act = (end != std::string::npos) ? line.substr(pos, end - pos) : line.substr(pos);
    auto slash = pkg_act.find('/');
    if (slash == std::string::npos) return "";
    std::string pkg = pkg_act.substr(0, slash);
    if (pkg.find('.') == std::string::npos) return "";
    return pkg;
}

inline std::string detect_foreground_package() {
    FILE* pipe = popen("dumpsys activity top 2>/dev/null | head -20", "r");
    if (!pipe) {
        LOG_W(TAG, "popen failed");
        return "";
    }

    char buf[512];
    std::string pkg;
    while (fgets(buf, sizeof(buf), pipe)) {
        pkg = parse_from_top_output(buf);
        if (!pkg.empty()) break;
    }
    pclose(pipe);

    if (pkg.empty()) {
        LOG_W(TAG, "dumpsys activity top returned no valid package");
    } else {
        LOG_I(TAG, "Resolved foreground: " + pkg);
    }
    return pkg;
}

} // namespace ForegroundFallback