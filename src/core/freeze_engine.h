#pragma once
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <atomic>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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

// ── RunningCache（移动定义到这里或单独文件，保持原样）──────
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
    void remove(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        cache_.erase(pkg);
    }
    std::set<std::string> get_all() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return cache_;
    }
private:
    RunningCache() = default;
    mutable std::mutex    mutex_;
    std::set<std::string> cache_;
};

class FreezeEngine {
public:
    static constexpr const char* TAG = "FreezeEngine";

    static FreezeEngine& instance() {
        static FreezeEngine inst;
        return inst;
    }

    // ── 公共接口（均被全局锁保护）─────────────────────────

    void on_app_foreground(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        cancel_pending_timer(pkg);
        do_unfreeze(pkg);
    }

    void on_app_background(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        auto state = AppStateStore::instance().get_state(pkg);
        if (state == FreezeState::FROZEN)     return;
        if (state == FreezeState::PENDING_BG) return;

        int delay = ConfigStore::instance().get().bg_freeze_delay_ms;
        schedule_freeze(pkg, delay);
    }

    void on_screen_off(const std::string& foreground_pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        const auto& cfg = ConfigStore::instance().get();
        cancel_screen_off_timer();

        int freeze_delay = cfg.screen_off_delay_ms;
        screen_off_timer_ = TimerManager::instance().schedule(freeze_delay, [this, foreground_pkg]{
            freeze_all_managed(foreground_pkg);
        });

        if (cfg.deep_sleep_on) {
            int deep_delay = freeze_delay + cfg.deep_sleep_delay_ms;
            DeepSleepManager::instance().schedule(deep_delay);
        }

        LOG_I(TAG, "Screen off, freeze in " + std::to_string(freeze_delay) + "ms");
    }

    void on_screen_on() {
        std::lock_guard<std::mutex> lk(mutex_);
        cancel_screen_off_timer();
        DeepSleepManager::instance().cancel_and_exit();
        LOG_I(TAG, "Screen on, silent");
    }

    void on_proc_died(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        RunningCache::instance().remove(pkg);
        cancel_pending_timer(pkg);
        AppStateStore::instance().erase(pkg);
    }

    void on_system_unfreeze(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(mutex_);
        auto state = AppStateStore::instance().get_state(pkg);
        if (state != FreezeState::FROZEN) return;

        int bounce = AppStateStore::instance().increment_bounce(pkg);
        int limit  = ConfigStore::instance().get().bounce_limit;

        if (bounce >= limit) {
            on_bounce_limit_reached(pkg);
            return;
        }
        LOG_W(TAG, pkg + " unfrozen by system (bounce=" + std::to_string(bounce) + "), re-freezing");
        do_freeze(pkg);
    }

    void start_freezer_guard() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (freezer_guard_started_) {
            LOG_W(TAG, "start_freezer_guard called more than once, ignoring");
            return;
        }
        freezer_guard_started_ = true;
        const int CHECK_INTERVAL_MS = 180000;
        schedule_freezer_check(CHECK_INTERVAL_MS);
    }

    void set_frozen_cgroups_map(struct bpf_map *map) {
        std::lock_guard<std::mutex> lk(mutex_);
        frozen_cgroups_map_ = map;
    }

    void update_uid_cache(const std::string& pkg, uint32_t uid) {
        std::lock_guard<std::mutex> lk(uid_cache_mutex_);
        pkg_to_uid_[pkg] = uid;
    }

private:
    FreezeEngine() = default;

    // ── 所有私有方法均在锁外被调用，调用者已持锁 ─────────

    void do_freeze(const std::string& pkg) {
        if (AppStateStore::instance().get_state(pkg) == FreezeState::FROZEN) return;
        if (!SafetyChecker::is_safe_to_freeze(pkg)) return;

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

        update_frozen_cgroups_map(pkg, true);

        // 冻结时剥夺非豁免应用的 AppOp
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

        update_frozen_cgroups_map(pkg, false);

        // 修正：恢复非豁免应用的 AppOp
        if (ConfigStore::instance().get().user_appop_restrict
            && !AppList::instance().is_user_exempt(pkg)) {
            AppOpManager::restore_all(pkg);
        }

        LOG_I(TAG, "Unfrozen: " + pkg);
    }

    void schedule_freeze(const std::string& pkg, int delay_ms) {
        AppStateStore::instance().set_state(pkg, FreezeState::PENDING_BG);
        auto id = TimerManager::instance().schedule(delay_ms, [this, pkg]{
            // 定时器回调也需要持有全局锁
            std::lock_guard<std::mutex> lk(mutex_);
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

    void cancel_screen_off_timer() {
        TimerManager::instance().cancel(screen_off_timer_);
        screen_off_timer_ = TimerManager::INVALID_TIMER;
    }

    void freeze_all_managed(const std::string& last_foreground) {
        // 定时器回调，调用者已持有锁
        auto snapshot = RunningCache::instance().get_all();
        for (const auto& pkg : snapshot) {
            if (should_skip_freeze(pkg)) continue;
            cancel_pending_timer(pkg);
            do_freeze(pkg);
        }
        // 确保前台应用也被冻结（可能不在 RunningCache 中？但通常会在）
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
            on_app_background(pkg);   // 自动持有锁
        });

        if (++freezer_suspect_count_ >= FREEZER_SUSPECT_THRESHOLD) {
            reassert_freezer_disabled();
            freezer_suspect_count_ = 0;
        }
    }

    void schedule_freezer_check(int interval_ms) {
        TimerManager::instance().schedule(interval_ms, [this, interval_ms]{
            std::lock_guard<std::mutex> lk(mutex_);
            if (is_system_freezer_enabled()) {
                LOG_W(TAG, "System freezer was re-enabled externally, disabling again");
                reassert_freezer_disabled();
            }
            schedule_freezer_check(interval_ms);
        });
    }

    bool is_system_freezer_enabled() {
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

    void update_frozen_cgroups_map(const std::string& /*pkg*/, bool frozen) {
        if (!frozen_cgroups_map_) return;

        uint64_t cg_id = read_our_frozen_cgroup_id();
        if (cg_id == 0) return;

        uint8_t val = 1;
        if (frozen) {
            bpf_map__update_elem(frozen_cgroups_map_, &cg_id, sizeof(cg_id),
                                 &val, sizeof(val), BPF_ANY);
        } else {
            bpf_map__delete_elem(frozen_cgroups_map_, &cg_id, sizeof(cg_id), 0);
        }
    }

    uint64_t read_our_frozen_cgroup_id() {
        auto content = FileUtil::read_str(std::string(Path::CGROUP_FROZEN) + "/cgroup.id");
        if (!content) return 0;
        try { return std::stoull(*content); } catch (...) { return 0; }
    }

    uint32_t pkg_to_uid(const std::string& pkg) {
        std::lock_guard<std::mutex> lk(uid_cache_mutex_);
        auto it = pkg_to_uid_.find(pkg);
        return (it != pkg_to_uid_.end()) ? it->second : 0;
    }

    // ── 成员变量 ────────────────────────────────────────
    std::mutex mutex_;   // 全局锁
    TimerManager::TimerId screen_off_timer_ = TimerManager::INVALID_TIMER;
    struct bpf_map *frozen_cgroups_map_ = nullptr;

    static constexpr int FREEZER_SUSPECT_THRESHOLD = 3;
    int freezer_suspect_count_ = 0;

    bool freezer_guard_started_ = false;   // 不再需要 atomic，被锁保护

    // uid 缓存
    mutable std::mutex uid_cache_mutex_;
    std::unordered_map<std::string, uint32_t> pkg_to_uid_;
};