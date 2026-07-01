#pragma once
#include <string>
#include <mutex>
#include "util/constants.h"
#include "util/timer.h"
#include "util/file_util.h"
#include "util/logger.h"

class DeepSleepManager {
public:
    static constexpr const char* TAG = "DeepSleep";

    static DeepSleepManager& instance() {
        static DeepSleepManager inst;
        return inst;
    }

    void schedule(int delay_ms) {
        std::lock_guard<std::mutex> lk(mutex_);
        cancel_pending_locked();
        cancelled_ = false;
        timer_id_ = TimerManager::instance().schedule(delay_ms, [this] {
            enter();
        });
        LOG_I(TAG, "Deep sleep scheduled in " + std::to_string(delay_ms) + "ms");
    }

    void cancel_and_exit() {
        std::lock_guard<std::mutex> lk(mutex_);
        cancelled_ = true;
        cancel_pending_locked();
        if (in_deep_sleep_) exit_locked();
    }

    bool is_active() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return in_deep_sleep_;
    }

private:
    DeepSleepManager() = default;

    void enter() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (cancelled_) {
            LOG_I(TAG, "Deep sleep cancelled before enter");
            return;
        }
        if (in_deep_sleep_) return;

        LOG_I(TAG, "Entering deep sleep");
        in_deep_sleep_ = true;

        system("cmd wifi set-scan-always-available disabled 2>/dev/null");
        system("settings put global ble_scan_always_enabled 0 2>/dev/null");
        system("cmd deviceidle force-idle deep 2>/dev/null");
        system("cmd jobscheduler reschedule-last-job 2>/dev/null");
        FileUtil::write_str(Path::DEEP_SLEEP_LOCK, "1");

        LOG_I(TAG, "Deep sleep active");
    }

    void exit_locked() {
        if (!in_deep_sleep_) return;
        LOG_I(TAG, "Exiting deep sleep");
        in_deep_sleep_ = false;

        system("cmd wifi set-scan-always-available enabled 2>/dev/null");
        system("settings put global ble_scan_always_enabled 1 2>/dev/null");
        system("cmd deviceidle unforce 2>/dev/null");
        ::unlink(Path::DEEP_SLEEP_LOCK);

        LOG_I(TAG, "Deep sleep exited");
    }

    void cancel_pending_locked() {
        TimerManager::instance().cancel(timer_id_);
        timer_id_ = TimerManager::INVALID_TIMER;
    }

    mutable std::mutex    mutex_;
    TimerManager::TimerId timer_id_ = TimerManager::INVALID_TIMER;
    bool                  in_deep_sleep_ = false;
    bool                  cancelled_ = false;
};