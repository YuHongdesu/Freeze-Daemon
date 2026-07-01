#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>
#include "util/timer.h"
#include "util/logger.h"

enum class FreezeState {
    RUNNING,      // 前台运行中
    PENDING_BG,   // 已切后台，等待延迟计时
    FROZEN,       // 已冻结
};

inline const char* state_name(FreezeState s) {
    switch (s) {
        case FreezeState::RUNNING:    return "RUNNING";
        case FreezeState::PENDING_BG: return "PENDING_BG";
        case FreezeState::FROZEN:     return "FROZEN";
    }
    return "UNKNOWN";
}

struct AppCtx {
    FreezeState          state         = FreezeState::RUNNING;
    int                  bounce_count  = 0;   // 被系统解冻的次数
    TimerManager::TimerId pending_timer = TimerManager::INVALID_TIMER;
};

// 纯状态仓库，只管状态读写，不执行任何 cgroup/shell 操作
class AppStateStore {
public:
    static constexpr const char* TAG = "AppStateStore";

    static AppStateStore& instance() {
        static AppStateStore inst;
        return inst;
    }

    FreezeState get_state(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = store_.find(pkg);
        return (it != store_.end()) ? it->second.state : FreezeState::RUNNING;
    }

    void set_state(const std::string& pkg, FreezeState state) {
        std::lock_guard<std::mutex> lk(mutex_);
        store_[pkg].state = state;
    }

    // 返回旧 timer id 并清除，由调用方负责 cancel
    TimerManager::TimerId take_pending_timer(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = store_.find(pkg);
        if (it == store_.end()) return TimerManager::INVALID_TIMER;
        auto id = it->second.pending_timer;
        it->second.pending_timer = TimerManager::INVALID_TIMER;
        return id;
    }

    void set_pending_timer(const std::string& pkg, TimerManager::TimerId id) {
        std::lock_guard<std::mutex> lk(mutex_);
        store_[pkg].pending_timer = id;
    }

    // 加固：显式检查存在才累加，避免隐式插入无意义的条目
    int increment_bounce(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = store_.find(pkg);
        if (it == store_.end()) return 0;   // 不存在则忽略
        return ++it->second.bounce_count;
    }

    void reset_bounce(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        store_[pkg].bounce_count = 0;
    }

    int get_bounce(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = store_.find(pkg);
        return (it != store_.end()) ? it->second.bounce_count : 0;
    }

    // 完全移除某 app 的状态记录（进程退出时调用，而非只是重置状态）
    // 否则每个曾经运行过的 app（含已卸载的）都会在 map 里留下永久条目，
    // 长期运行会造成内存缓慢增长
    void erase(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        store_.erase(pkg);
    }

    // 返回所有已冻结的包名快照（用于 Web UI 状态上报）
    std::vector<std::string> get_frozen_packages() const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<std::string> result;
        for (const auto& [pkg, ctx] : store_) {
            if (ctx.state == FreezeState::FROZEN) result.push_back(pkg);
        }
        return result;
    }

private:
    AppStateStore() = default;

    mutable std::mutex                       mutex_;
    std::unordered_map<std::string, AppCtx> store_;
};