#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdio>
#include "util/logger.h"

// 平台层：冻结前安全检查，防止打断音乐/导航/投屏等前台服务
namespace SafetyChecker {

constexpr const char* TAG = "SafetyChecker";
constexpr int CACHE_TTL_MS = 500;

struct CacheEntry {
    bool is_safe;
    std::chrono::steady_clock::time_point checked_at;
};

inline std::mutex& cache_mutex() {
    static std::mutex m;
    return m;
}
inline std::unordered_map<std::string, CacheEntry>& cache() {
    static std::unordered_map<std::string, CacheEntry> c;
    return c;
}

// ── 转义 shell 参数（单引号），同时可用作 grep 固定字符串 ──
inline std::string shell_escape(const std::string& s) {
    std::string escaped;
    escaped.reserve(s.size() + 4);
    escaped += '\'';
    for (char c : s) {
        if (c == '\'') escaped += "'\\''";
        else           escaped += c;
    }
    escaped += '\'';
    return escaped;
}

// 一次 dumpsys 调用同时检查前台服务、AudioFocus 播放状态、MediaSession 播放状态
inline bool query_is_safe(const std::string& pkg) {
    std::string safe_pkg = shell_escape(pkg);

    // 使用 grep -F 进行固定字符串匹配，避免 . 等正则特殊字符误匹配
    std::string cmd = "sh -c \""
        "dumpsys activity services " + safe_pkg + " 2>/dev/null | grep -cF 'isForeground=true'; "
        "dumpsys audio 2>/dev/null | grep -A2 -F 'packageName=" + safe_pkg + "' | grep -cF 'state: started'; "
        "dumpsys media_session 2>/dev/null | grep -A3 -F " + safe_pkg + " | grep -cF 'state=PlaybackState {state=3'"
        "\"";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return true;   // 查询失败时保守放行（不阻止冻结）

    int fg_count = 0, audio_count = 0, session_count = 0;
    int n = fscanf(pipe, "%d%d%d", &fg_count, &audio_count, &session_count);
    pclose(pipe);

    if (n != 3) {
        LOG_W(TAG, "Failed to parse safety check output for " + pkg);
        return true;  // 解析失败时保守放行
    }

    if (fg_count > 0) {
        LOG_I(TAG, pkg + " has foreground service, skip freeze");
        return false;
    }
    if (audio_count > 0) {
        LOG_I(TAG, pkg + " is playing audio (AudioFocus), skip freeze");
        return false;
    }
    if (session_count > 0) {
        LOG_I(TAG, pkg + " is playing media (MediaSession), skip freeze");
        return false;
    }
    return true;
}

// 综合安全检查：极短 TTL 缓存防止毫秒级重复调用，不影响实时性
inline bool is_safe_to_freeze(const std::string& pkg) {
    auto now = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(cache_mutex());
        auto it = cache().find(pkg);
        if (it != cache().end()) {
            auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.checked_at).count();
            if (age_ms < CACHE_TTL_MS) return it->second.is_safe;
        }
    }

    bool safe = query_is_safe(pkg);

    std::lock_guard<std::mutex> lk(cache_mutex());
    cache()[pkg] = {safe, now};
    return safe;
}

} // namespace SafetyChecker