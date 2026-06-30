#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdio>
#include "util/logger.h"

// 平台层：冻结前安全检查，防止打断音乐/导航/投屏等前台服务
//
// 性能说明：原实现每次 do_freeze 都触发两次独立 dumpsys 调用（约 20-40ms/次），
// 现合并为一次 dumpsys 调用（同时检查 foreground service 和 audio），
// 并加极短 TTL 缓存（500ms）只防止同一 app 在毫秒级内被连续调用两次，
// 不会因缓存导致漏判正在播放的音乐（TTL 远小于人类操作间隔）
namespace SafetyChecker {

constexpr const char* TAG = "SafetyChecker";
constexpr int CACHE_TTL_MS = 500;

struct CacheEntry {
    bool is_safe;
    std::chrono::steady_clock::time_point checked_at;
};

inline std::mutex&                                      cache_mutex() {
    static std::mutex m;
    return m;
}
inline std::unordered_map<std::string, CacheEntry>&     cache() {
    static std::unordered_map<std::string, CacheEntry> c;
    return c;
}

// 一次 dumpsys 调用同时检查前台服务、AudioFocus 播放状态、MediaSession 播放状态
//
// AudioFocus（dumpsys audio）和 MediaSession（dumpsys media_session）
// 检测的是两类不同但有重叠的播放场景：前者捕获直接占用音频输出的播放器，
// 后者捕获通过官方 MediaSession API 上报状态的播放器（部分视频/播客类
// app 即使未持有 AudioFocus —— 例如静音播放、画中画模式 —— 仍会正确
// 上报 MediaSession 状态）。借鉴 Frosty _media_active() 的检测点
// （PlaybackState{state=3} 即 STATE_PLAYING），两者合并查询提高覆盖率，
// 命中任一即视为不安全冻结
inline bool query_is_safe(const std::string& pkg) {
    std::string cmd = "sh -c \"dumpsys activity services " + pkg
                    + " 2>/dev/null | grep -c 'isForeground=true'; "
                    + "dumpsys audio 2>/dev/null | grep -A2 'packageName=" + pkg
                    + "' | grep -c 'state: started'; "
                    + "dumpsys media_session 2>/dev/null | grep -A3 '" + pkg
                    + "' | grep -c 'state=PlaybackState {state=3'\"";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return true;  // 查询失败时保守放行（不阻止冻结）

    int fg_count = 0, audio_count = 0, session_count = 0;
    fscanf(pipe, "%d", &fg_count);
    fscanf(pipe, "%d", &audio_count);
    fscanf(pipe, "%d", &session_count);
    pclose(pipe);

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
