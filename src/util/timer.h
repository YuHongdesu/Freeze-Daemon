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

// 单次定时器管理器，基于 timerfd + epoll，无忙等
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

    // 在 delay_ms 毫秒后执行一次 cb，返回 timer id
    TimerId schedule(int delay_ms, Callback cb) {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd < 0) { LOG_E(TAG, "timerfd_create failed"); return INVALID_TIMER; }

        arm_timerfd(fd, delay_ms);

        TimerId id = fd;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            timers_[id] = std::move(cb);
        }
        add_to_epoll(fd);
        return id;
    }

    // 取消尚未触发的定时器
    void cancel(TimerId id) {
        if (id == INVALID_TIMER) return;
        // 先从 map 中摘除，防止 epoll 线程触发后执行已取消的 cb
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (timers_.find(id) == timers_.end()) return;  // 已触发或已取消
            timers_.erase(id);
        }
        remove_from_epoll(id);
        ::close(id);
    }

    void start() {
        epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
        worker_ = std::thread(&TimerManager::run, this);
    }

    void stop() {
        running_ = false;
        worker_.join();
        ::close(epoll_fd_);
    }

private:
    TimerManager() : running_(true) {}

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

    void remove_from_epoll(int fd) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    void fire(int fd) {
        uint64_t exp;
        ::read(fd, &exp, sizeof(exp));   // 消费事件

        Callback cb;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            auto it = timers_.find(fd);
            if (it == timers_.end()) return;
            cb = std::move(it->second);
            timers_.erase(it);
        }
        ::close(fd);
        if (cb) cb();
    }

    void run() {
        constexpr int MAX_EVENTS = 16;
        epoll_event events[MAX_EVENTS];
        while (running_) {
            int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, 500);
            for (int i = 0; i < n; ++i) fire(events[i].data.fd);
        }
    }

    int                                   epoll_fd_{-1};
    std::atomic<bool>                     running_;
    std::mutex                            mutex_;
    std::unordered_map<TimerId, Callback> timers_;
    std::thread                           worker_;
};
