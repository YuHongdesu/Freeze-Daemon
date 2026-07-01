#pragma once
#include <string>
#include <atomic>
#include <mutex>
#include "platform/appop_manager.h"
#include "util/constants.h"
#include "util/timer.h"
#include "util/file_util.h"
#include "util/logger.h"

// 业务层：深度休眠管理器
// 触发条件：息屏后超过 deep_sleep_delay_ms 且屏幕仍未亮起
// 动作：在 cgroup 冻结基础上，额外执行系统级休眠优化
// 恢复条件：亮屏时立即撤销所有深度休眠动作
class DeepSleepManager {
public:
    static constexpr const char* TAG = "DeepSleep";

    static DeepSleepManager& instance() {
        static DeepSleepManager inst;
        return inst;
    }

    // 息屏时调度深度休眠（在普通冻结之后再延迟触发）
    void schedule(int delay_ms) {
        std::lock_guard<std::mutex> lk(mutex_);
        cancel_pending_locked();
        cancelled_ = false;                         // 新的调度，清除取消标记
        timer_id_ = TimerManager::instance().schedule(delay_ms, [this] {
            enter();
        });
        LOG_I(TAG, "Deep sleep scheduled in " + std::to_string(delay_ms) + "ms");
    }

    // 亮屏时立即取消并退出深度休眠
    void cancel_and_exit() {
        std::lock_guard<std::mutex> lk(mutex_);
        cancelled_ = true;                          // 阻止尚未开始的 enter
        cancel_pending_locked();
        if (in_deep_sleep_) exit_locked();
    }

    bool is_active() const { return in_deep_sleep_.load(); }

private:
    DeepSleepManager() = default;

    void enter() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (cancelled_) {                           // 在锁内检查是否已被取消
            LOG_I(TAG, "Deep sleep cancelled before enter");
            return;
        }
        if (in_deep_sleep_) return;                 // 幂等

        LOG_I(TAG, "Entering deep sleep");
        in_deep_sleep_ = true;

        // 释放锁？不，这些命令很快，且我们需要保证原子性
        // 但 system() 可能阻塞，不过深度休眠操作不是性能热点，可以接受
        system("cmd wifi set-scan-always-available disabled 2>/dev/null");
        system("settings put global ble_scan_always_enabled 0 2>/dev/null");
        system("cmd deviceidle force-idle deep 2>/dev/null");
        system("cmd jobscheduler reschedule-last-job 2>/dev/null");
        FileUtil::write_str(Path::DEEP_SLEEP_LOCK, "1");

        LOG_I(TAG, "Deep sleep active");
    }

    void exit_locked() {                            // 调用者已持有锁
        if (!in_deep_sleep_) return;
        LOG_I(TAG, "Exiting deep sleep");
        in_deep_sleep_ = false;

        system("cmd wifi set-scan-always-available enabled 2>/dev/null");
        system("settings put global ble_scan_always_enabled 1 2>/dev/null");
        system("cmd deviceidle unforce 2>/dev/null");
        ::unlink(Path::DEEP_SLEEP_LOCK);

        LOG_I(TAG, "Deep sleep exited");
    }

    void cancel_pending_locked() {                  // 调用者已持有锁
        TimerManager::instance().cancel(timer_id_);
        timer_id_ = TimerManager::INVALID_TIMER;
    }

    std::mutex            mutex_;
    TimerManager::TimerId timer_id_ = TimerManager::INVALID_TIMER;
    bool                  in_deep_sleep_ = false;   // 受 mutex_ 保护，无需 atomic
    bool                  cancelled_     = false;   // 受 mutex_ 保护
};