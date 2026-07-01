#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdio>
#include "util/logger.h"

class AppLabelCache {
public:
    static AppLabelCache& instance() {
        static AppLabelCache inst;
        return inst;
    }

    // 启动时调用一次，批量获取所有应用标签
    void build() {
        std::lock_guard<std::mutex> lk(mutex_);
        cache_.clear();

        auto append_from_pm = [this](const char* filter) {
            // 使用 cmd package get-app-label 获取标签，输出格式：package:pkg label:标签
            std::string cmd = "pm list packages -U ";
            cmd += filter;
            cmd += " 2>/dev/null | while read line; do "
                   "pkg=$(echo $line | sed 's/package:\\(.*\\) uid:.*/\\1/'); "
                   "label=$(cmd package get-app-label \"$pkg\" 2>/dev/null); "
                   "echo \"package:$pkg label:$label\"; "
                   "done";

            FILE* pipe = popen(cmd.c_str(), "r");
            if (!pipe) return;
            char buf[512];
            while (fgets(buf, sizeof(buf), pipe)) {
                std::string line(buf);
                auto p = line.find("package:");
                if (p == std::string::npos) continue;
                auto e = line.find(" label:");
                if (e == std::string::npos) continue;
                std::string pkg = line.substr(p + 8, e - (p + 8));
                std::string label = line.substr(e + 7);
                // 去除尾部换行和空白
                while (!label.empty() && (label.back() == '\n' || label.back() == '\r'))
                    label.pop_back();
                if (!label.empty()) cache_[pkg] = label;
            }
            pclose(pipe);
        };

        append_from_pm("-3");   // 用户应用
        append_from_pm("-s");   // 系统应用

        LOG_I("AppLabelCache", "Built cache with " + std::to_string(cache_.size()) + " apps");
    }

    std::string get_label(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = cache_.find(pkg);
        return (it != cache_.end()) ? it->second : pkg;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> cache_;
};