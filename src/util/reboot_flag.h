#pragma once
#include <string>
#include <vector>
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

// 标记某个类别的变更需要重启才生效（重复标记同一类别不会产生重复行）
inline void mark(const std::string& category) {
    // 防御性创建目录，不依赖 service.sh 一定先执行过
    system("mkdir -p /data/adb/modules/freeze-daemon/tmp 2>/dev/null");

    auto existing = FileUtil::read_lines_as_set(FLAG_FILE);
    if (existing.count(category)) return;  // 已标记，避免重复写入
    existing.insert(category);
    FileUtil::write_lines(FLAG_FILE, existing);
    LOG_I(TAG, "Marked needs-reboot: " + category);
}

// 查询当前是否有任何待生效的变更
inline bool has_pending() {
    return FileUtil::file_exists(FLAG_FILE)
        && !FileUtil::read_lines_as_set(FLAG_FILE).empty();
}

// 获取所有待生效变更的类别列表（用于 Web UI 展示具体原因）
inline std::vector<std::string> pending_categories() {
    auto set = FileUtil::read_lines_as_set(FLAG_FILE);
    return {set.begin(), set.end()};
}

// Daemon 重启后清除所有标记（在 main() 启动序列里调用）
inline void clear_all() {
    std::remove(FLAG_FILE);
}

} // namespace RebootFlag
