#pragma once
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <atomic>
#include <bpf/libbpf.h>
#include "core/app_state.h"
#include "core/app_list.h"
#include "core/config_store.h"
#include "core/deep_sleep_manager.h"
#include "platform/cgroup_manager.h"
#include "platform/pid_cache.h"
#include "platform/safety_checker.h"
#include "platform/appop_manager.h"
#include "util/timer.h"
#include "util/logger.h"

// 运行中包名缓存（由 eBPF 进程事件维护，供息屏批量冻结使用）
// 定义在 FreezeEngine 之前，因为 FreezeEngine 方法中直接使用
class RunningCache {
public:
    static RunningCache& instance() {
        static RunningCache inst;
        return inst;
    }
    void add(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        cache_.insert(pkg);
    }
    // 进程退出时必须调用，防止缓存无限增长
    void remove(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        cache_.erase(pkg);
    }
    // 返回快照副本，避免调用方持锁期间死锁
    std::set<std::string> get_all() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return cache_;
    }
private:
    RunningCache() = default;
    mutable std::mutex    mutex_;
    std::set<std::string> cache_;
};

// 业务层：冻结引擎，唯一协调状态机、cgroup、AppOp、定时器的地方
class FreezeEngine {
public:
    static constexpr const char* TAG = "FreezeEngine";

    static FreezeEngine& instance() {
        static FreezeEngine inst;
        return inst;
    }

    // ── 对外事件接口（由 EventDispatcher 调用）────────────────

    void on_app_foreground(const std::string& pkg) {
        cancel_pending_timer(pkg);
        do_unfreeze(pkg);
    }

    void on_app_background(const std::string& pkg) {
        auto state = AppStateStore::instance().get_state(pkg);
        if (state == FreezeState::FROZEN)     return;  // 幂等
        if (state == FreezeState::PENDING_BG) return;  // 计时器已在跑

        int delay = ConfigStore::instance().get().bg_freeze_delay_ms;
        schedule_freeze(pkg, delay);
    }

    void on_screen_off(const std::string& foreground_pkg) {
        const auto& cfg = ConfigStore::instance().get();

        // 每次息屏前先取消旧 timer，防止覆盖导致无法取消
        cancel_screen_off_timer();

        int freeze_delay = cfg.screen_off_delay_ms;
        screen_off_timer_ = TimerManager::instance().schedule(freeze_delay, [this, foreground_pkg]{
            freeze_all_managed(foreground_pkg);
        });

        // 深度休眠：在普通冻结之后再延迟触发
        if (cfg.deep_sleep_on) {
            int deep_delay = freeze_delay + cfg.deep_sleep_delay_ms;
            DeepSleepManager::instance().schedule(deep_delay);
        }

        LOG_I(TAG, "Screen off, freeze in " + std::to_string(freeze_delay) + "ms");
    }

    void on_screen_on() {
        // 静默策略：亮屏不解冻任何 app，等用户点开才解冻
        cancel_screen_off_timer();
        DeepSleepManager::instance().cancel_and_exit();
        LOG_I(TAG, "Screen on, silent");
    }

    // 进程真正退出，清理 RunningCache 和状态记录
    void on_proc_died(const std::string& pkg) {
        RunningCache::instance().remove(pkg);
        // 取消任何挂起的计时器，防止其在条目被清除后仍然触发
        cancel_pending_timer(pkg);
        // 完全移除状态记录（而非仅重置为 RUNNING），
        // 避免每个曾经运行过的 app（含已卸载的）永久占据 AppStateStore
        AppStateStore::instance().erase(pkg);
    }

    // 系统主动解冻感知（依赖 our_frozen_cgroups map，由 do_freeze 写入）
    void on_system_unfreeze(const std::string& pkg) {
        auto state = AppStateStore::instance().get_state(pkg);
        if (state != FreezeState::FROZEN) return;  // 非我们冻的，忽略

        int bounce = AppStateStore::instance().increment_bounce(pkg);
        int limit  = ConfigStore::instance().get().bounce_limit;

        if (bounce >= limit) {
            on_bounce_limit_reached(pkg);
            return;
        }
        LOG_W(TAG, pkg + " unfrozen by system (bounce=" + std::to_string(bounce) + "), re-freezing");
        do_freeze(pkg);
    }

    // ── 系统 Freezer 防御层 ────────────────────────────────────
    // 关闭系统 Freezer 后理论上不该再被解冻，若仍频繁触发 bounce，
    // 说明 device_config 可能被某些 ROM 的系统服务重新置位
    // 用周期定时器检查（而非阻塞 shell 循环），不影响 Daemon 启动流程
    //
    // 防重复调用：guard 链是自我重新调度的无限循环，一旦启动两次
    // 会产生两条永远无法停止的并行检查链（无对应 cancel 机制），
    // 用标志位确保整个 Daemon 生命周期内只启动一次
    void start_freezer_guard() {
        if (freezer_guard_started_.exchange(true)) {
            LOG_W(TAG, "start_freezer_guard called more than once, ignoring");
            return;
        }
        const int CHECK_INTERVAL_MS = 180000;  // 3 分钟检查一次：这是兜底防御，
                                                // 真正的快速响应靠 bounce 计数触发，
                                                // 不需要高频轮询
        schedule_freezer_check(CHECK_INTERVAL_MS);
    }

    // ── BPF map fd 注入（由 BpfLoader 在加载后调用）────────────
    // 用户态需要持有 our_frozen_cgroups map 的 fd 来写入
    void set_frozen_cgroups_map_fd(int fd) {
        frozen_cgroups_map_fd_ = fd;
    }

private:
    FreezeEngine() = default;

    // ── 核心操作（幂等保证在此）────────────────────────────────

    void do_freeze(const std::string& pkg) {
        if (AppStateStore::instance().get_state(pkg) == FreezeState::FROZEN) return;
        if (!SafetyChecker::is_safe_to_freeze(pkg)) return;

        // 优先用 PidCache（eBPF 实时维护），降级到 /proc 扫描
        uint32_t uid  = pkg_to_uid(pkg);
        auto pids = (uid > 0)
                  ? PidCache::instance().get_pids_by_uid(uid)
                  : CgroupManager::get_pids_by_package(pkg);

        if (pids.empty()) {
            LOG_D(TAG, pkg + " has no running process, skip");
            return;
        }

        CgroupManager::move_pids_to_frozen(pids);
        AppStateStore::instance().set_state(pkg, FreezeState::FROZEN);
        AppStateStore::instance().reset_bounce(pkg);

        // 冻结后把 cgroup id 写入 our_frozen_cgroups map
        update_frozen_cgroups_map(pkg, true);

        // 用户 app（非白名单）额外剥夺 AppOp
        if (ConfigStore::instance().get().user_appop_restrict
            && !AppList::instance().is_user_exempt(pkg)) {
            AppOpManager::revoke_all(pkg);
        }

        LOG_I(TAG, "Frozen: " + pkg + " (" + std::to_string(pids.size()) + " pids)");
    }

    void do_unfreeze(const std::string& pkg) {
        if (AppStateStore::instance().get_state(pkg) == FreezeState::RUNNING) return;

        uint32_t uid  = pkg_to_uid(pkg);
        auto pids = (uid > 0)
                  ? PidCache::instance().get_pids_by_uid(uid)
                  : CgroupManager::get_pids_by_package(pkg);

        CgroupManager::move_pids_to_active(pids);
        AppStateStore::instance().set_state(pkg, FreezeState::RUNNING);
        AppStateStore::instance().reset_bounce(pkg);

        // 从 our_frozen_cgroups map 移除
        update_frozen_cgroups_map(pkg, false);

        // 恢复 AppOp（白名单 app 和系统 app 解冻时恢复权限）
        if (AppList::instance().is_user_exempt(pkg)) {
            AppOpManager::restore_all(pkg);
        }

        LOG_I(TAG, "Unfrozen: " + pkg);
    }

    // ── 定时器管理 ──────────────────────────────────────────────

    void schedule_freeze(const std::string& pkg, int delay_ms) {
        AppStateStore::instance().set_state(pkg, FreezeState::PENDING_BG);
        auto id = TimerManager::instance().schedule(delay_ms, [this, pkg]{
            if (AppStateStore::instance().get_state(pkg) != FreezeState::PENDING_BG) return;
            do_freeze(pkg);
        });
        AppStateStore::instance().set_pending_timer(pkg, id);
        LOG_D(TAG, pkg + " freeze in " + std::to_string(delay_ms) + "ms");
    }

    void cancel_pending_timer(const std::string& pkg) {
        auto id = AppStateStore::instance().take_pending_timer(pkg);
        TimerManager::instance().cancel(id);
    }

    // 独立封装息屏 timer 取消，防止覆盖
    void cancel_screen_off_timer() {
        TimerManager::instance().cancel(screen_off_timer_);
        screen_off_timer_ = TimerManager::INVALID_TIMER;
    }

    // 息屏后冻结所有受管理的 app（含息屏前的前台 app）
    void freeze_all_managed(const std::string& last_foreground) {
        auto snapshot = RunningCache::instance().get_all();
        for (const auto& pkg : snapshot) {
            if (should_skip_freeze(pkg)) continue;
            cancel_pending_timer(pkg);
            do_freeze(pkg);
        }
        // 息屏前的前台 app 也冻结（屏幕已关，用户不再操作）
        if (!last_foreground.empty() && !should_skip_freeze(last_foreground)) {
            cancel_pending_timer(last_foreground);
            do_freeze(last_foreground);
        }
        LOG_I(TAG, "All managed apps frozen on screen off");
    }

    bool should_skip_freeze(const std::string& pkg) {
        return AppList::instance().is_user_exempt(pkg);
    }

    void on_bounce_limit_reached(const std::string& pkg) {
        int backoff = ConfigStore::instance().get().bounce_backoff_ms;
        LOG_W(TAG, pkg + " bounce limit reached, back off " + std::to_string(backoff) + "ms");
        AppStateStore::instance().set_state(pkg, FreezeState::RUNNING);
        AppStateStore::instance().reset_bounce(pkg);
        TimerManager::instance().schedule(backoff, [this, pkg]{
            on_app_background(pkg);
        });

        // 同一个 app 短时间内触发退避，是系统 Freezer 仍在运行的信号
        // 提高怀疑计数，达到阈值后主动重新下发关闭指令
        if (++freezer_suspect_count_ >= FREEZER_SUSPECT_THRESHOLD) {
            reassert_freezer_disabled();
            freezer_suspect_count_ = 0;
        }
    }

    // 周期性检查 device_config 是否被外部改回 true，如果是则重新下发
    void schedule_freezer_check(int interval_ms) {
        TimerManager::instance().schedule(interval_ms, [this, interval_ms]{
            if (is_system_freezer_enabled()) {
                LOG_W(TAG, "System freezer was re-enabled externally, disabling again");
                reassert_freezer_disabled();
            }
            schedule_freezer_check(interval_ms);  // 重新调度，形成周期检查
        });
    }

    bool is_system_freezer_enabled() {
        // 读取 device_config 的本地缓存文件判断当前状态
        // /data/local/tmp 不持久，实际值需要通过 getprop 镜像或专用查询
        // 此处用 system() 调用 device_config get 并捕获返回值
        FILE* pipe = popen("device_config get activity_manager_native_boot use_freezer 2>/dev/null", "r");
        if (!pipe) return false;
        char buf[16] = {};
        bool ok = fgets(buf, sizeof(buf), pipe) != nullptr;
        pclose(pipe);
        if (!ok) return false;
        return std::string(buf).find("true") != std::string::npos;
    }

    void reassert_freezer_disabled() {
        system("device_config put activity_manager_native_boot use_freezer false 2>/dev/null");
        system("settings put global cached_apps_freezer disabled 2>/dev/null");
        LOG_I(TAG, "System freezer re-disabled");
    }

    // ── BPF map 维护 ────────────────────────────

    // 冻结/解冻时同步更新 our_frozen_cgroups BPF map
    // BPF 侧通过此 map 判断系统解冻行为是否影响我们的 cgroup
    void update_frozen_cgroups_map(const std::string& /*pkg*/, bool frozen) {
        if (frozen_cgroups_map_fd_ < 0) return;

        // 读取我们的 frozen cgroup 的 id
        uint64_t cg_id = read_our_frozen_cgroup_id();
        if (cg_id == 0) return;

        uint8_t val = 1;
        if (frozen) {
            bpf_map_update_elem(frozen_cgroups_map_fd_, &cg_id, &val, BPF_ANY);
        } else {
            bpf_map_delete_elem(frozen_cgroups_map_fd_, &cg_id);
        }
    }

    uint64_t read_our_frozen_cgroup_id() {
        // 读取 /sys/fs/cgroup/freeze_daemon/frozen/cgroup.id
        auto content = FileUtil::read_str(std::string(Path::CGROUP_FROZEN) + "/cgroup.id");
        if (!content) return 0;
        try { return std::stoull(*content); } catch (...) { return 0; }
    }

    // ── uid 映射（从 EventDispatcher 的缓存间接获取）────────────
    // 简化：包名→uid 通过静态映射文件获取，避免再次 popen
    uint32_t pkg_to_uid(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(uid_cache_mutex_);
        auto it = pkg_to_uid_.find(pkg);
        return (it != pkg_to_uid_.end()) ? it->second : 0;
    }

public:
    // EventDispatcher 构建 uid 缓存后同步给 FreezeEngine
    void update_uid_cache(const std::string& pkg, uint32_t uid) {
        std::lock_guard<std::mutex> lk(uid_cache_mutex_);
        pkg_to_uid_[pkg] = uid;
    }

private:
    TimerManager::TimerId screen_off_timer_ = TimerManager::INVALID_TIMER;
    int frozen_cgroups_map_fd_ = -1;

    // 系统 Freezer 怀疑计数：连续多次 bounce_limit 触发，怀疑 device_config 被重置
    static constexpr int FREEZER_SUSPECT_THRESHOLD = 3;
    int freezer_suspect_count_ = 0;

    // 防止 start_freezer_guard 被多次调用，产生无法停止的并行检查链
    std::atomic<bool> freezer_guard_started_{false};

    mutable std::mutex uid_cache_mutex_;
    std::unordered_map<std::string, uint32_t> pkg_to_uid_;
};
