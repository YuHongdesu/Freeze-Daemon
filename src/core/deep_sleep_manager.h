#pragma once
#include <string>
#include <atomic>
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
        cancel_pending();
        timer_id_ = TimerManager::instance().schedule(delay_ms, [this]{
            enter();
        });
        LOG_I(TAG, "Deep sleep scheduled in " + std::to_string(delay_ms) + "ms");
    }

    // 亮屏时立即取消并退出深度休眠
    void cancel_and_exit() {
        cancel_pending();
        if (in_deep_sleep_.load()) exit();
    }

    bool is_active() const { return in_deep_sleep_.load(); }

private:
    DeepSleepManager() = default;

    void enter() {
        if (in_deep_sleep_.exchange(true)) return;   // 幂等：已在深度休眠
        LOG_I(TAG, "Entering deep sleep");

        // 1. 禁用 Wi-Fi 扫描（减少网络唤醒）
        system("cmd wifi set-scan-always-available disabled 2>/dev/null");

        // 2. 禁用蓝牙扫描（减少 BLE 广播唤醒）
        system("settings put global ble_scan_always_enabled 0 2>/dev/null");

        // 3. 强制进入 Deep Doze（立即而不是等待 Doze 自然触发）
        system("cmd deviceidle force-idle deep 2>/dev/null");

        // 4. 限制 Job Scheduler（减少后台 job 唤醒）
        system("cmd jobscheduler reschedule-last-job 2>/dev/null");

        // 5. 写标记文件（供 service.sh 亮屏恢复时检测）
        FileUtil::write_str(Path::DEEP_SLEEP_LOCK, "1");

        LOG_I(TAG, "Deep sleep active");
    }

    void exit() {
        if (!in_deep_sleep_.exchange(false)) return;  // 幂等：已不在深度休眠
        LOG_I(TAG, "Exiting deep sleep");

        // 恢复 Wi-Fi 扫描
        system("cmd wifi set-scan-always-available enabled 2>/dev/null");

        // 恢复蓝牙扫描
        system("settings put global ble_scan_always_enabled 1 2>/dev/null");

        // 退出强制 Doze
        system("cmd deviceidle unforce 2>/dev/null");

        // 移除标记文件
        ::unlink(Path::DEEP_SLEEP_LOCK);

        LOG_I(TAG, "Deep sleep exited");
    }

    void cancel_pending() {
        TimerManager::instance().cancel(timer_id_);
        timer_id_ = TimerManager::INVALID_TIMER;
    }

    TimerManager::TimerId timer_id_ = TimerManager::INVALID_TIMER;
    std::atomic<bool>     in_deep_sleep_{false};
};
