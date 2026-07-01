#pragma once
#include <functional>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "logger.h"

class TimerManager {
public:
    using TimerId  = int;
    using Callback = std::function<void()>;

    static constexpr TimerId INVALID_TIMER = -1;
    static constexpr const char* TAG = "Timer";

    static TimerManager& instance() {
        static TimerManager inst;
        return inst;
    }

    TimerId schedule(int delay_ms, Callback cb) {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd < 0) {
            LOG_E(TAG, "timerfd_create failed");
            return INVALID_TIMER;
        }

        arm_timerfd(fd, delay_ms);

        TimerId id;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            id = next_id_++;
            timers_[id] = {fd, std::move(cb)};
        }

        add_to_epoll(fd);
        return id;
    }

    void cancel(TimerId id) {
        if (id == INVALID_TIMER) return;

        std::lock_guard<std::mutex> lk(mutex_);
        auto it = timers_.find(id);
        if (it == timers_.end()) return;

        int fd = it->second.fd;
        timers_.erase(it);

        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        ::close(fd);
    }

    void start() {
        if (started_.exchange(true)) return;
        epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
        running_ = true;
        worker_ = std::thread(&TimerManager::run, this);
    }

    void stop() {
        if (!started_.exchange(false)) return;
        running_ = false;
        if (worker_.joinable()) worker_.join();
        {
            std::lock_guard<std::mutex> lk(mutex_);
            for (auto& [id, entry] : timers_) {
                epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, entry.fd, nullptr);
                ::close(entry.fd);
            }
            timers_.clear();
        }
        ::close(epoll_fd_);
        epoll_fd_ = -1;
    }

private:
    struct TimerEntry {
        int      fd;
        Callback cb;
    };

    TimerManager() : running_(false), started_(false), next_id_(0) {}

    void arm_timerfd(int fd, int delay_ms) {
        itimerspec spec{};
        spec.it_value.tv_sec  = delay_ms / 1000;
        spec.it_value.tv_nsec = (delay_ms % 1000) * 1'000'000L;
        timerfd_settime(fd, 0, &spec, nullptr);
    }

    void add_to_epoll(int fd) {
        epoll_event ev{};
        ev.events  = EPOLLIN | EPOLLONESHOT;
        ev.data.fd = fd;
        epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
    }

    void fire(int fd) {
        uint64_t exp;
        ::read(fd, &exp, sizeof(exp));

        Callback cb;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            for (auto it = timers_.begin(); it != timers_.end(); ++it) {
                if (it->second.fd == fd) {
                    cb = std::move(it->second.cb);
                    timers_.erase(it);
                    break;
                }
            }
        }
        if (cb) cb();
        ::close(fd);
    }

    void run() {
        constexpr int MAX_EVENTS = 16;
        epoll_event events[MAX_EVENTS];
        while (running_) {
            int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, 500);
            for (int i = 0; i < n; ++i) {
                fire(events[i].data.fd);
            }
        }
    }

    int                              epoll_fd_{-1};
    std::atomic<bool>                running_{false};
    std::atomic<bool>                started_{false};  // 必须在 next_id_ 之前声明
    std::mutex                       mutex_;
    std::unordered_map<TimerId, TimerEntry> timers_;
    TimerId                          next_id_ = 0;
    std::thread                      worker_;
};