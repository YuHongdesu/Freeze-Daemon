#pragma once
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <mutex>
#include "util/logger.h"

// 平台层：uid/pid 缓存，由 eBPF 进程事件实时维护
// 消除每次冻结/解冻时遍历 /proc 的开销
//
// 同时维护反向索引（pid → uid），供 EventDispatcher 在收到
// uid=0 的 sched_switch 事件时优先查内存而非临时读 /proc/[pid]/status，
// 后者存在进程刚退出导致文件消失的竞态窗口
class PidCache {
public:
    static constexpr const char* TAG = "PidCache";

    static PidCache& instance() {
        static PidCache inst;
        return inst;
    }

    // eBPF 感知到进程被调度时调用
    void on_pid_active(uint32_t uid, uint32_t pid) {
        std::lock_guard<std::mutex> lk(mutex_);
        uid_to_pids_[uid].insert(pid);
        pid_to_uid_[pid] = uid;
    }

    // eBPF 感知到进程退出时调用
    void on_pid_died(uint32_t uid, uint32_t pid) {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = uid_to_pids_.find(uid);
        if (it != uid_to_pids_.end()) {
            it->second.erase(pid);
            if (it->second.empty()) uid_to_pids_.erase(it);
        }
        pid_to_uid_.erase(pid);
    }

    // 查询某 uid 下所有存活的 pid（返回副本）
    std::vector<int> get_pids_by_uid(uint32_t uid) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = uid_to_pids_.find(uid);
        if (it == uid_to_pids_.end()) return {};
        return {it->second.begin(), it->second.end()};
    }

    // 反向查询：pid → uid（缓存未命中返回 0）
    uint32_t get_uid_by_pid(uint32_t pid) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = pid_to_uid_.find(pid);
        return (it != pid_to_uid_.end()) ? it->second : 0;
    }

    // uid 下是否有存活进程
    bool has_running(uint32_t uid) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = uid_to_pids_.find(uid);
        return it != uid_to_pids_.end() && !it->second.empty();
    }

private:
    PidCache() = default;
    mutable std::mutex                                          mutex_;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>>  uid_to_pids_;
    std::unordered_map<uint32_t, uint32_t>                      pid_to_uid_;
};
