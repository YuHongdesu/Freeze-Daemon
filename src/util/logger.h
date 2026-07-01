#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <atomic>
#include <cstdio>
#include <ctime>
#include "constants.h"

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static constexpr size_t ROTATE_THRESHOLD_BYTES = 1024 * 1024;  // 1MB

    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void set_level(LogLevel level) { min_level_.store(level); }

    void log(LogLevel level, const std::string& tag, const std::string& msg) {
        if (level < min_level_.load()) return;
        std::string line = format_line(level, tag, msg);
        {
            std::lock_guard<std::mutex> lk(queue_mutex_);
            queue_.push(std::move(line));
        }
        cv_.notify_one();
    }

    ~Logger() {
        stop();
    }

private:
    Logger() : min_level_(LogLevel::INFO), running_(true) {
        open_log_file();
        flush_thread_ = std::thread(&Logger::flush_loop, this);
    }

    void open_log_file() {
        file_.open(Path::LOG_FILE, std::ios::app);
        if (!file_.is_open()) {
            // 文件打开失败时至少向 stderr 报告，避免无日志
            std::cerr << "Logger: failed to open " << Path::LOG_FILE << std::endl;
        }
    }

    std::string format_line(LogLevel level, const std::string& tag, const std::string& msg) {
        std::ostringstream oss;
        oss << now_str() << " [" << level_char(level) << "] " << tag << ": " << msg;
        return oss.str();
    }

    // 线程安全的 localtime 封装
    std::string now_str() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);   // POSIX 线程安全版本
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%m-%d %H:%M:%S");
        return oss.str();
    }

    char level_char(LogLevel l) {
        switch (l) {
            case LogLevel::DEBUG: return 'D';
            case LogLevel::INFO:  return 'I';
            case LogLevel::WARN:  return 'W';
            case LogLevel::ERROR: return 'E';
        }
        return '?';
    }

    void flush_loop() {
        constexpr int FLUSH_INTERVAL_MS = 1000;
        constexpr size_t BATCH_THRESHOLD = 64;

        while (running_) {
            std::queue<std::string> batch;
            {
                std::unique_lock<std::mutex> lk(queue_mutex_);
                cv_.wait_for(lk, std::chrono::milliseconds(FLUSH_INTERVAL_MS),
                             [this]{ return queue_.size() >= BATCH_THRESHOLD || !running_; });
                std::swap(batch, queue_);
            }
            write_batch(batch);
        }
        // 退出前刷出剩余日志
        std::queue<std::string> remaining;
        { std::lock_guard<std::mutex> lk(queue_mutex_); std::swap(remaining, queue_); }
        write_batch(remaining);
    }

    void write_batch(std::queue<std::string>& batch) {
        if (batch.empty()) return;
        std::lock_guard<std::mutex> lk(file_mutex_);
        while (!batch.empty()) {
            const std::string& line = batch.front();
            std::cout << line << "\n";
            if (file_.is_open()) {
                file_ << line << "\n";
            }
            batch.pop();
        }
        if (file_.is_open()) {
            file_.flush();
            rotate_if_needed();
        } else {
            // 尝试重新打开日志文件（可能之前轮转失败或磁盘空间恢复）
            open_log_file();
        }
    }

    void rotate_if_needed() {
        if (!file_.is_open()) return;
        auto size = file_.tellp();
        if (size < 0 || static_cast<size_t>(size) < ROTATE_THRESHOLD_BYTES) return;

        file_.close();

        std::string old_path = std::string(Path::LOG_FILE) + ".old";
        std::remove(old_path.c_str());
        if (std::rename(Path::LOG_FILE, old_path.c_str()) != 0) {
            // 如果 rename 失败，尝试重新打开原文件继续写入（避免丢失）
            open_log_file();
            return;
        }

        open_log_file();  // 新建空日志文件
    }

    void stop() {
        running_ = false;
        cv_.notify_all();
        if (flush_thread_.joinable()) flush_thread_.join();
    }

    std::atomic<LogLevel>  min_level_;
    std::atomic<bool>      running_;
    std::mutex             queue_mutex_;
    std::mutex             file_mutex_;
    std::condition_variable cv_;
    std::queue<std::string> queue_;
    std::ofstream          file_;
    std::thread            flush_thread_;
};

#define LOG_D(tag, msg) Logger::instance().log(LogLevel::DEBUG, tag, msg)
#define LOG_I(tag, msg) Logger::instance().log(LogLevel::INFO,  tag, msg)
#define LOG_W(tag, msg) Logger::instance().log(LogLevel::WARN,  tag, msg)
#define LOG_E(tag, msg) Logger::instance().log(LogLevel::ERROR, tag, msg)