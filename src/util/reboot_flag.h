#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <sys/stat.h>
#include "file_util.h"
#include "constants.h"
#include "logger.h"

// 借鉴 Frosty service.sh 的 *_needs_reboot 标记文件模式：
// 某些配置变更不会立即生效（例如需要重新加载 eBPF、重启 cgroup 子树），
// 用标记文件记录"哪些类别的变更待生效"，Web UI 据此提示用户重启 Daemon
//
// 与 Frosty 的差异：Frosty 是多个独立 shell 脚本各自写自己的 *_needs_reboot
// 文件（如 kernel_needs_reboot、ram_needs_reboot），我们的场景更简单
// （只有一个 Daemon 进程），所以合并成单一标记文件、内部分类存储
namespace RebootFlag {

constexpr const char* TAG = "RebootFlag";
constexpr const char* FLAG_FILE = "/data/adb/modules/freeze-daemon/tmp/needs_reboot.txt";

// 内部互斥锁，保护文件读-改-写操作
inline std::mutex& flag_mutex() {
    static std::mutex m;
    return m;
}

// 标记某个类别的变更需要重启才生效（重复标记同一类别不会产生重复行）
inline void mark(const std::string& category) {
    std::lock_guard<std::mutex> lk(flag_mutex());

    // 确保目录存在（用 mkdir 代替 system，更安全、更快）
    mkdir("/data/adb/modules/freeze-daemon/tmp", 0755);

    auto existing = FileUtil::read_lines_as_set(FLAG_FILE);
    if (existing.count(category)) return;  // 已标记，避免重复写入
    existing.insert(category);
    FileUtil::write_lines(FLAG_FILE, existing);
    LOG_I(TAG, "Marked needs-reboot: " + category);
}

// 查询当前是否有任何待生效的变更
inline bool has_pending() {
    std::lock_guard<std::mutex> lk(flag_mutex());
    return FileUtil::file_exists(FLAG_FILE)
        && !FileUtil::read_lines_as_set(FLAG_FILE).empty();
}

// 获取所有待生效变更的类别列表（用于 Web UI 展示具体原因）
inline std::vector<std::string> pending_categories() {
    std::lock_guard<std::mutex> lk(flag_mutex());
    auto set = FileUtil::read_lines_as_set(FLAG_FILE);
    return {set.begin(), set.end()};
}

// Daemon 重启后清除所有标记（在 main() 启动序列里调用）
inline void clear_all() {
    std::lock_guard<std::mutex> lk(flag_mutex());
    std::remove(FLAG_FILE);
}

} // namespace RebootFlag