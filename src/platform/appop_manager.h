#pragma once
#include <string>
#include <vector>
#include <cstdio>
#include "util/constants.h"
#include "util/file_util.h"
#include "util/logger.h"

// 平台层：AppOp 权限剥夺，只做 shell 命令执行，不含策略逻辑
namespace AppOpManager {

constexpr const char* TAG = "AppOpManager";
constexpr const char* RESTRICT_LIST_PATH = "/data/adb/modules/freeze-daemon/config/appop_restrict_list.txt";

// ── 工具函数：安全转义 shell 参数 ──────────────────────────
// 用单引号包裹并转义内部的单引号，防止命令注入
inline std::string safe_arg(const std::string& s) {
    std::string escaped;
    escaped.reserve(s.size() + 4);
    escaped += '\'';
    for (char c : s) {
        if (c == '\'') {
            escaped += "'\\''";
        } else {
            escaped += c;
        }
    }
    escaped += '\'';
    return escaped;
}

// 唯一数据源：从 config/appop_restrict_list.txt 加载
// 与 scripts/service.sh 的 load_restrict_ops() 读取同一份文件，
// 消除之前 C++ constexpr 数组和 shell 脚本各自硬编码一份的重复维护问题
inline std::vector<std::string> load_restrict_ops() {
    auto lines = FileUtil::read_lines_as_set(RESTRICT_LIST_PATH);
    if (lines.empty()) {
        LOG_W(TAG, "appop_restrict_list.txt empty or missing, using fallback");
        return {"RUN_IN_BACKGROUND", "RUN_ANY_IN_BACKGROUND", "WAKE_LOCK"};
    }
    return {lines.begin(), lines.end()};
}

// 进程启动时加载一次，后续复用（文件极小，I/O 成本可忽略，但避免每次调用都重新解析）
inline const std::vector<std::string>& restrict_ops() {
    static std::vector<std::string> ops = load_restrict_ops();
    return ops;
}

inline bool run_cmd(const std::string& cmd) {
    int ret = system(cmd.c_str());
    return ret == 0;
}

// 剥夺单个 AppOp 权限（已转义参数）
inline bool revoke_op(const std::string& pkg, const std::string& op) {
    std::string cmd = "cmd appops set " + safe_arg(pkg) + " " + safe_arg(op) + " deny 2>/dev/null";
    return run_cmd(cmd);
}

// 恢复单个 AppOp 权限为默认（已转义参数）
inline bool restore_op(const std::string& pkg, const std::string& op) {
    std::string cmd = "cmd appops set " + safe_arg(pkg) + " " + safe_arg(op) + " default 2>/dev/null";
    return run_cmd(cmd);
}

// 剥夺所有受限 AppOp（用于系统黑名单 app 和非白名单用户 app）
inline void revoke_all(const std::string& pkg) {
    for (const auto& op : restrict_ops()) {
        if (!revoke_op(pkg, op)) {
            LOG_W(TAG, "Failed to revoke " + op + " for " + pkg);
        }
    }
    LOG_I(TAG, "AppOps revoked: " + pkg);
}

// 恢复所有受限 AppOp（用于加入白名单时恢复用户 app）
inline void restore_all(const std::string& pkg) {
    for (const auto& op : restrict_ops()) {
        restore_op(pkg, op);
    }
    LOG_I(TAG, "AppOps restored: " + pkg);
}

// 踢出 deviceidle（Doze）白名单（仅系统黑名单 app 使用）
inline void kick_from_doze(const std::string& pkg) {
    std::string cmd = "cmd deviceidle whitelist -" + safe_arg(pkg) + " 2>/dev/null";
    run_cmd(cmd);
    LOG_I(TAG, "Doze whitelist removed: " + pkg);
}

// 恢复进入 deviceidle 白名单
inline void restore_doze(const std::string& pkg) {
    std::string cmd = "cmd deviceidle whitelist +" + safe_arg(pkg) + " 2>/dev/null";
    run_cmd(cmd);
}

} // namespace AppOpManager