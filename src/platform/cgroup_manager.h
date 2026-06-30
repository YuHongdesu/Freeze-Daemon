#pragma once
#include <string>
#include <vector>
#include <dirent.h>
#include <cctype>
#include <cerrno>
#include <sys/stat.h>
#include "util/file_util.h"
#include "util/constants.h"
#include "util/logger.h"

// 平台层：只负责 cgroup v2 文件操作，不含业务逻辑
namespace CgroupManager {

constexpr const char* TAG = "Cgroup";

inline std::string cgroup_procs_path(const std::string& cgroup_dir) {
    return cgroup_dir + "/cgroup.procs";
}

inline std::string cgroup_freeze_path(const std::string& cgroup_dir) {
    return cgroup_dir + "/cgroup.freeze";
}

inline bool create_dir(const std::string& path) {
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

// 初始化独立 cgroup 子树，与系统 uid_N cgroup 隔离
inline bool init_cgroup_tree() {
    if (!create_dir(Path::CGROUP_ROOT))  { LOG_E(TAG, "Cannot create root cgroup");   return false; }
    if (!create_dir(Path::CGROUP_FROZEN)){ LOG_E(TAG, "Cannot create frozen cgroup");  return false; }
    if (!create_dir(Path::CGROUP_ACTIVE)){ LOG_E(TAG, "Cannot create active cgroup");  return false; }

    // frozen 子组永远保持冻结，迁入即冻结
    if (!FileUtil::write_str(cgroup_freeze_path(Path::CGROUP_FROZEN), "1")) {
        LOG_E(TAG, "Cannot set frozen cgroup.freeze=1");
        return false;
    }
    // active 子组永远解冻
    FileUtil::write_str(cgroup_freeze_path(Path::CGROUP_ACTIVE), "0");

    LOG_I(TAG, "Cgroup tree initialized");
    return true;
}

// 把进程批量迁入指定 cgroup（一次 open，多次 write，一次 close）
// 注意：cgroup.procs 每次 write 仍只接受单个 pid（v2 限制），
// 但合并 fd 打开关闭可以显著减少系统调用次数
inline bool move_pids_to(const std::string& cgroup_dir, const std::vector<int>& pids) {
    if (pids.empty()) return true;

    std::string path = cgroup_procs_path(cgroup_dir);
    FILE* f = fopen(path.c_str(), "w");
    if (!f) {
        LOG_E(TAG, "Cannot open " + path);
        return false;
    }

    bool all_ok = true;
    for (int pid : pids) {
        // 每次 write 后立即 fflush，确保单个 pid 写入失败不影响后续
        if (fprintf(f, "%d", pid) < 0 || fflush(f) != 0) {
            LOG_W(TAG, "Failed to move pid " + std::to_string(pid) + " to " + cgroup_dir);
            all_ok = false;
        }
    }
    fclose(f);
    return all_ok;
}

inline bool move_pids_to_frozen(const std::vector<int>& pids) {
    return move_pids_to(Path::CGROUP_FROZEN, pids);
}

inline bool move_pids_to_active(const std::vector<int>& pids) {
    return move_pids_to(Path::CGROUP_ACTIVE, pids);
}

// 查询某包名下所有 pid（通过遍历 /proc 目录，只读实际存在的进程）
inline std::vector<int> get_pids_by_package(const std::string& pkg) {
    std::vector<int> pids;
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return pids;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // 跳过非数字目录
        if (entry->d_type != DT_DIR) continue;
        const char* name = entry->d_name;
        if (!isdigit(name[0])) continue;

        int pid = atoi(name);
        if (pid <= 0) continue;

        std::string cmdline_path = "/proc/" + std::string(name) + "/cmdline";
        auto content = FileUtil::read_str(cmdline_path);
        if (!content || content->empty()) continue;

        // cmdline 用 \0 分隔，取第一段作为进程名
        size_t null_pos = content->find('\0');
        std::string proc_name = (null_pos != std::string::npos)
                              ? content->substr(0, null_pos)
                              : *content;

        // 匹配主进程（com.xxx）或子进程（com.xxx:service）
        if (proc_name == pkg || proc_name.rfind(pkg + ":", 0) == 0) {
            pids.push_back(pid);
        }
    }
    closedir(proc_dir);
    return pids;
}

} // namespace CgroupManager
