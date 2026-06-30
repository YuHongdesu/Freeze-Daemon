#pragma once
#include <set>
#include <string>
#include <mutex>
#include "util/file_util.h"
#include "util/constants.h"
#include "util/logger.h"

// 管理白名单（用户app豁免）和黑名单（系统app限制）的纯数据层
class AppList {
public:
    static constexpr const char* TAG = "AppList";

    static AppList& instance() {
        static AppList inst;
        return inst;
    }

    // ── 用户app白名单（豁免冻结）──────────────────────────

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

    // ── 系统app黑名单（限制目标）──────────────────────────

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

    bool modify_set(std::set<std::string>& set, const std::string& pkg,
                    SetOp op, const std::string& path) {
        if (pkg.empty()) return false;
        std::lock_guard<std::mutex> lk(mutex_);
        if (op == SetOp::ADD)    set.insert(pkg);
        else                     set.erase(pkg);
        return FileUtil::write_lines(path, set);
    }

    mutable std::mutex    mutex_;
    std::set<std::string> user_whitelist_;
    std::set<std::string> sys_blacklist_;
};
