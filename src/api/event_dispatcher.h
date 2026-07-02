#pragma once
#include <string>
#include <sstream>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <cstdint>
#include "platform/bpf_loader.h"
#include "platform/pid_cache.h"
#include "core/freeze_engine.h"
#include "util/constants.h"
#include "util/file_util.h"
#include "util/logger.h"

// 接口层：eBPF 事件路由，唯一职责是 uid→包名 映射和事件分发。
//
// 关键修复：main.cpp 里的 schedule_top_app_refresh()（shell 轮询前后台）
// 原来无条件与 eBPF 事件路径并行运行，且直接调用
// FreezeEngine::on_app_foreground/on_app_background，完全绕开了本类的
// on_foreground/on_background（也就绕开了 RunningCache::add）。这导致：
//   1. 如果 eBPF 从未真正产生过前后台事件（例如 top-app cgroup 路径在
//      新设备上找不到——即使 BpfLoader::load() 本身返回成功），
//      RunningCache 永远是空的，息屏时 freeze_all_managed() 找不到
//      任何要冻结的后台应用，冻结功能形同虚设。
//   2. 即使 eBPF 正常工作，shell 轮询仍然按固定 30 秒周期反复调用
//      on_app_foreground（哪怕前台应用没变），带来不必要的
//      cancel_pending_timer + do_unfreeze 噪音，与 eBPF 路径产生竞态。
//
// 现在把 on_foreground/on_background 提升为公共、通用的"前后台切换
// 上报"入口（不再假设调用方一定是 eBPF），main.cpp 的 shell 轮询也
// 改为调用这两个方法而不是直接捅 FreezeEngine，这样无论前后台事件
// 从哪条路径来，RunningCache 都能被正确维护。同时新增
// last_ebpf_event_age_ms()，供 main.cpp 判断 eBPF 是否"看起来在正常
// 工作"，从而只在真正需要时才让 shell 轮询接管驱动权，而不是无条件
// 双路并行。
class EventDispatcher {
public:
    static constexpr const char* TAG = "Dispatcher";

    void dispatch(const FreezeEvent& ev) {
        mark_ebpf_alive();

        // 屏幕事件不需要 uid→pkg 解析
        if (ev.type == BpfEvent::SCREEN_ON)  { on_screen_on();  return; }
        if (ev.type == BpfEvent::SCREEN_OFF) { on_screen_off(); return; }

        // sched_switch 探针发出的 APP_FOREGROUND/APP_BACKGROUND 事件 uid 恒为 0
        // （内核侧只知道 pid，不反查 uid），需要在用户态反查。
        //
        // Bug 修复（竞态窗口）：原实现直接读 /proc/[pid]/status，
        // 进程刚退出时文件可能已消失导致反查失败。
        // 现在优先查 PidCache 的内存反向索引（无 I/O、无竞态），
        // 该索引由 fork/exit 事件实时维护，只有缓存未命中
        // （例如 Daemon 刚启动、尚未观测到该进程的 fork 事件）
        // 才退化到读 /proc 作为兜底。
        uint32_t resolved_uid = ev.uid;
        if (resolved_uid == 0) {
            resolved_uid = PidCache::instance().get_uid_by_pid(ev.pid);
        }
        if (resolved_uid == 0) {
            resolved_uid = resolve_uid_from_pid(ev.pid);  // 兜底：/proc 读取
        }
        if (resolved_uid == 0) return;  // 仍然反查失败（进程已退出等），丢弃本次事件

        // 维护 PidCache（所有含 uid/pid 的事件都更新）
        // 注意：PROC_DIED 必须在上面的 uid 反查之后再调用 on_pid_died，
        // 否则会先抹除反向索引导致本次事件自己都解析不出 uid
        if (ev.type == BpfEvent::PROC_DIED) {
            PidCache::instance().on_pid_died(resolved_uid, ev.pid);
        } else {
            PidCache::instance().on_pid_active(resolved_uid, ev.pid);
        }

        std::string pkg = resolve_pkg(resolved_uid);
        if (pkg.empty()) return;

        switch (ev.type) {
            case BpfEvent::APP_FOREGROUND: on_foreground(pkg); break;
            case BpfEvent::APP_BACKGROUND: on_background(pkg); break;
            case BpfEvent::SYS_UNFREEZE:   on_sys_unfreeze(pkg); break;
            case BpfEvent::PROC_DIED:      on_proc_died(pkg); break;
            default:
                LOG_W(TAG, "Unknown event type: " + std::to_string(ev.type));
        }
    }

    void refresh_uid_cache() {
        uid_to_pkg_ = build_uid_cache();
        // 同步给 FreezeEngine 的 pkg→uid 映射
        for (const auto& [uid, pkg] : uid_to_pkg_) {
            FreezeEngine::instance().update_uid_cache(pkg, uid);
        }
        LOG_I(TAG, "UID cache refreshed: " + std::to_string(uid_to_pkg_.size()) + " entries");
    }

    // ── 通用前后台上报入口（公开，供 eBPF 路径和 main.cpp 的 shell
    //    轮询 fallback 路径共用，确保 RunningCache 只有一处维护逻辑）──

    // 供 shell 轮询判断"eBPF 最近是否还在正常产出事件"，单位毫秒。
    // 从未收到过任何 eBPF 事件时返回一个很大的数，表示"从未健康过"。
    int64_t last_ebpf_event_age_ms() const {
        int64_t last = last_ebpf_event_ms_.load();
        if (last == 0) return INT64_MAX;
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        return now - last;
    }

    void notify_foreground(const std::string& pkg) { on_foreground(pkg); }
    void notify_background(const std::string& pkg) { on_background(pkg); }

private:
    void mark_ebpf_alive() {
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        last_ebpf_event_ms_.store(now);
    }

    void on_foreground(const std::string& pkg) {
        current_foreground_pkg_ = pkg;
        RunningCache::instance().add(pkg);
        FreezeEngine::instance().on_app_foreground(pkg);
    }

    void on_background(const std::string& pkg) {
        if (current_foreground_pkg_ == pkg) current_foreground_pkg_.clear();
        FreezeEngine::instance().on_app_background(pkg);
    }

    // PROC_DIED 事件触发完整清理（RunningCache + 状态机）
    void on_proc_died(const std::string& pkg) {
        if (current_foreground_pkg_ == pkg) current_foreground_pkg_.clear();
        FreezeEngine::instance().on_proc_died(pkg);
    }

    void on_screen_on()  { FreezeEngine::instance().on_screen_on(); }
    void on_screen_off() { FreezeEngine::instance().on_screen_off(current_foreground_pkg_); }
    void on_sys_unfreeze(const std::string& pkg) { FreezeEngine::instance().on_system_unfreeze(pkg); }

    // ── pid → uid 反查（用于 uid=0 的 sched_switch 事件）──────────

    // 读 /proc/[pid]/status 的 "Uid:" 行，比 popen 任何命令都轻量
    // 格式: "Uid:\t10086\t10086\t10086\t10086\n"（真实/有效/保存/文件系统 uid）
    uint32_t resolve_uid_from_pid(uint32_t pid) {
        if (pid == 0) return 0;
        std::string path = "/proc/" + std::to_string(pid) + "/status";
        auto content = FileUtil::read_str(path);
        if (!content) return 0;  // 进程可能已退出

        auto pos = content->find("Uid:");
        if (pos == std::string::npos) return 0;
        pos += 4;  // 跳过 "Uid:"

        try {
            return static_cast<uint32_t>(std::stoul(content->substr(pos)));
        } catch (...) {
            return 0;
        }
    }

    // ── uid → pkg 解析（缓存优先，未命中时查 packages.list）──────

    std::string resolve_pkg(uint32_t uid) {
        auto it = uid_to_pkg_.find(uid);
        if (it != uid_to_pkg_.end()) return it->second;

        std::string pkg = query_pkg_from_packages_list(uid);
        if (!pkg.empty()) {
            uid_to_pkg_[uid] = pkg;
            FreezeEngine::instance().update_uid_cache(pkg, uid);
        }
        return pkg;
    }

    // 读 /data/system/packages.list（比 popen pm 快 10x，无子进程开销）
    std::string query_pkg_from_packages_list(uint32_t target_uid) {
        // 格式: com.example.app 10086 0 /data/user/0/com.example.app ...
        auto content = FileUtil::read_str("/data/system/packages.list");
        if (!content) return query_pkg_from_pm(target_uid);  // 降级

        std::istringstream iss(*content);
        std::string line;
        while (std::getline(iss, line)) {
            size_t sp1 = line.find(' ');
            if (sp1 == std::string::npos) continue;
            size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string::npos) continue;

            std::string uid_str = line.substr(sp1 + 1, sp2 - sp1 - 1);
            try {
                if (std::stoul(uid_str) == target_uid)
                    return line.substr(0, sp1);
            } catch (...) { continue; }
        }
        return "";
    }

    // 降级方案：popen pm（仅在 packages.list 不可读时使用）
    std::string query_pkg_from_pm(uint32_t uid) {
        std::string cmd = "pm list packages -U 2>/dev/null | grep ' uid:"
                        + std::to_string(uid) + "' | head -1";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        char buf[256] = {};
        bool ok = fgets(buf, sizeof(buf), pipe) != nullptr;
        pclose(pipe);
        if (!ok) return "";

        std::string s(buf);
        auto pkg_pos = s.find("package:");
        auto uid_pos = s.find(" uid:");
        if (pkg_pos == std::string::npos || uid_pos == std::string::npos) return "";
        return s.substr(pkg_pos + 8, uid_pos - (pkg_pos + 8));
    }

    // 启动时一次性构建完整缓存（读 packages.list，无 popen 开销）
    std::unordered_map<uint32_t, std::string> build_uid_cache() {
        std::unordered_map<uint32_t, std::string> cache;
        auto content = FileUtil::read_str("/data/system/packages.list");
        if (!content) return cache;

        std::istringstream iss(*content);
        std::string line;
        while (std::getline(iss, line)) {
            size_t sp1 = line.find(' ');
            if (sp1 == std::string::npos) continue;
            size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string::npos) continue;

            std::string pkg     = line.substr(0, sp1);
            std::string uid_str = line.substr(sp1 + 1, sp2 - sp1 - 1);
            try {
                cache[std::stoul(uid_str)] = pkg;
            } catch (...) { continue; }
        }
        return cache;
    }

    std::unordered_map<uint32_t, std::string> uid_to_pkg_;
    std::string current_foreground_pkg_;

    // 0 表示"从未收到过任何 eBPF 事件"；有值时是 steady_clock 毫秒时间戳
    std::atomic<int64_t> last_ebpf_event_ms_{0};
};

