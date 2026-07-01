#pragma once
#include <set>
#include <string>
#include <mutex>
#include "util/file_util.h"
#include "util/constants.h"
#include "util/logger.h"

class AppList {
public:
    static constexpr const char* TAG = "AppList";

    static AppList& instance() {
        static AppList inst;
        return inst;
    }

    // ── 用户白名单 ──────────────────────────────────────
    bool is_user_exempt(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        return user_whitelist_.count(pkg) > 0;
    }

    bool add_user_exempt(const std::string& pkg) {
        return modify_set(user_whitelist_, pkg, SetOp::ADD, Path::USER_WHITELIST);
    }

    bool remove_user_exempt(const std::string& pkg) {
        return modify_set(user_whitelist_, pkg, SetOp::REMOVE, Path::USER_WHITELIST);
    }

    std::set<std::string> get_user_whitelist() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return user_whitelist_;
    }

    // ── 系统黑名单 ──────────────────────────────────────
    bool is_sys_restricted(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        return sys_blacklist_.count(pkg) > 0;
    }

    bool add_sys_restricted(const std::string& pkg) {
        return modify_set(sys_blacklist_, pkg, SetOp::ADD, Path::SYS_BLACKLIST);
    }

    bool remove_sys_restricted(const std::string& pkg) {
        return modify_set(sys_blacklist_, pkg, SetOp::REMOVE, Path::SYS_BLACKLIST);
    }

    std::set<std::string> get_sys_blacklist() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return sys_blacklist_;
    }

    void reload() {
        std::lock_guard<std::mutex> lk(mutex_);
        user_whitelist_ = FileUtil::read_lines_as_set(Path::USER_WHITELIST);
        sys_blacklist_  = FileUtil::read_lines_as_set(Path::SYS_BLACKLIST);
        LOG_I(TAG, "Lists reloaded: whitelist=" + std::to_string(user_whitelist_.size())
                   + " blacklist=" + std::to_string(sys_blacklist_.size()));
    }

private:
    AppList() { reload(); }

    enum class SetOp { ADD, REMOVE };

    // 原子修改：先构建新集合，写入文件成功后再替换内存集合
    bool modify_set(std::set<std::string>& set, const std::string& pkg,
                    SetOp op, const std::string& path) {
        if (pkg.empty()) return false;
        std::lock_guard<std::mutex> lk(mutex_);

        auto target = set;  // 复制
        if (op == SetOp::ADD) target.insert(pkg);
        else                  target.erase(pkg);

        if (!FileUtil::write_lines(path, target)) return false;

        set = std::move(target);
        return true;
    }

    mutable std::mutex    mutex_;
    std::set<std::string> user_whitelist_;
    std::set<std::string> sys_blacklist_;
};