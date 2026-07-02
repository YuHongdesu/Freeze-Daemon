#pragma once
#include <string>
#include <fstream>
#include <functional>
#include <thread>
#include <atomic>
#include <cstddef>    // offsetof
#include <cstring>    // strcmp（原来靠间接 include 才能编译通过，显式加上更稳）
#include <dirent.h>   // opendir/readdir/closedir，用于 top-app cgroup 路径发现
#include <sys/stat.h> // stat/S_ISDIR
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "util/constants.h"
#include "util/logger.h"

// 关键修复：必须与内核态 freeze_monitor.bpf.c 的 freeze_event 逐字节一致。
// 显式 packed，不依赖编译器默认对齐规则（用户态 clang/gcc 和内核态
// bpf-target clang 的默认对齐行为可能不同，之前正是两边对齐规则
// 不一致导致 uid/pid 被读出垃圾值）。offset 断言确保任何一边的字段
// 顺序被意外改动时，编译期就会报错，而不是运行时静默读错内存。
struct __attribute__((packed)) FreezeEvent {
    uint8_t  type;
    uint8_t  _pad[3];
    uint32_t uid;
    uint32_t pid;
};
static_assert(sizeof(FreezeEvent) == 12, "FreezeEvent must match kernel-side freeze_event layout exactly");
static_assert(offsetof(FreezeEvent, uid) == 4, "uid offset must match kernel-side layout");
static_assert(offsetof(FreezeEvent, pid) == 8, "pid offset must match kernel-side layout");

using EventCallback = std::function<void(const FreezeEvent&)>;

class BpfLoader {
public:
    static constexpr const char* TAG      = "BpfLoader";
    static constexpr const char* OBJ_PATH = "/data/adb/modules/freeze-daemon/bin/freeze_monitor.bpf.o";

    bool load(EventCallback cb) {
        callback_ = std::move(cb);

        obj_ = bpf_object__open(OBJ_PATH);
        if (!obj_) { LOG_E(TAG, "bpf_object__open failed"); return false; }

        skip_unstable_probes();

        if (bpf_object__load(obj_)) {
            LOG_E(TAG, "bpf_object__load failed");
            bpf_object__close(obj_);
            obj_ = nullptr;
            return false;
        }

        if (!attach_probes_gracefully()) {
            LOG_E(TAG, "Failed to attach any BPF probes, giving up");
            bpf_object__close(obj_);
            obj_ = nullptr;
            return false;
        }

        ring_buf_ = setup_ringbuf();
        if (!ring_buf_) {
            bpf_object__close(obj_);
            obj_ = nullptr;
            return false;
        }

        top_app_map_        = find_map("top_app_cgroup_id");
        frozen_cgroup_map_  = find_map("our_frozen_cgroups");
        if (!top_app_map_)   LOG_W(TAG, "top_app_cgroup_id map not found");
        if (!frozen_cgroup_map_) LOG_W(TAG, "our_frozen_cgroups map not found");

        refresh_top_app_cgroup();

        LOG_I(TAG, "eBPF loaded and attached");
        return true;
    }

    bool refresh_top_app_cgroup() {
        if (!top_app_map_) return false;

        uint64_t cg_id = read_top_app_cgroup_id();
        if (cg_id == 0) {
            // 如果系统没有可用的 cgroup2 top-app，不累加计数，避免无意义日志
            static bool v2_healthy = []{
                std::ifstream test("/sys/fs/cgroup/cgroup.controllers");
                return test.is_open();
            }();
            if (!v2_healthy) return false;  // 静默退出，不增加 fail 计数
            if (++consecutive_fail_count_ >= FAIL_WARN_THRESHOLD) {
                LOG_W(TAG, "top-app cgroup.id read failed " +
                           std::to_string(consecutive_fail_count_) +
                           " times, foreground detection may be stale");
            }
            return false;
        }
        consecutive_fail_count_ = 0;

        uint32_t key = 0;
        int ret = bpf_map__update_elem(top_app_map_, &key, sizeof(key),
                                       &cg_id, sizeof(cg_id), BPF_ANY);
        if (ret != 0) {
            LOG_W(TAG, "Failed to update top_app_cgroup_id");
            return false;
        }
        return true;
    }

    int consecutive_fail_count() const { return consecutive_fail_count_; }

    struct bpf_map *frozen_cgroup_map() const { return frozen_cgroup_map_; }

    void start_loop() {
        running_ = true;
        loop_thread_ = std::thread(&BpfLoader::poll_loop, this);
    }

    void join() {
        if (loop_thread_.joinable()) loop_thread_.join();
    }

    void stop() {
        running_ = false;
        if (loop_thread_.joinable()) loop_thread_.join();
        if (ring_buf_) { ring_buffer__free(ring_buf_); ring_buf_ = nullptr; }
        if (obj_)      { bpf_object__close(obj_);      obj_      = nullptr; }
    }

private:
    void poll_loop() {
        while (running_) {
            ring_buffer__poll(ring_buf_, 200);
        }
    }

    void skip_unstable_probes() {
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj_) {
            const char *name = bpf_program__name(prog);
            if (strcmp(name, "on_cgroup_migrate") == 0) {
                bpf_program__set_autoload(prog, false);
                LOG_W(TAG, "Skipping on_cgroup_migrate (kernel BTF type not available)");
            }
        }
    }

    bool attach_probes_gracefully() {
        struct bpf_program *prog;
        int attached = 0;
        int total = 0;

        bpf_object__for_each_program(prog, obj_) {
            total++;
            if (!bpf_program__autoload(prog)) {
                LOG_I(TAG, "Skipping attach for unloaded program: " +
                          std::string(bpf_program__name(prog)));
                continue;
            }

            struct bpf_link *link = bpf_program__attach(prog);
            if (!link) {
                LOG_W(TAG, std::string("Failed to attach: ") + bpf_program__name(prog) +
                            ", errno: " + std::to_string(errno));
                continue;
            }
            attached++;
        }

        if (attached == 0) {
            LOG_E(TAG, "No BPF programs could be attached");
            return false;
        }

        LOG_I(TAG, "Attached " + std::to_string(attached) + "/" + std::to_string(total) + " programs");
        return true;
    }

    ring_buffer* setup_ringbuf() {
        struct bpf_map *map = bpf_object__find_map_by_name(obj_, "events");
        if (!map) { LOG_E(TAG, "Cannot find events map"); return nullptr; }
        return ring_buffer__new(bpf_map__fd(map), on_event_raw, this, nullptr);
    }

    struct bpf_map* find_map(const char* name) {
        return bpf_object__find_map_by_name(obj_, name);
    }

    // 读取指定路径下的 cgroup.id，成功返回 >0 的值，失败返回 0
    uint64_t read_cgroup_id_at(const std::string& top_app_dir) {
        std::ifstream f(top_app_dir + "/cgroup.id");
        if (!f.is_open()) return 0;
        uint64_t id = 0;
        f >> id;
        return (!f.fail() && id > 0) ? id : 0;
    }

    // 在 base_dir 下有限深度（最多 3 层）递归查找名为 "top-app" 的目录。
    // Android 15+ 部分厂商 ROM（含小米 HyperOS）开启了
    // PRODUCT_CGROUP_V2_SYS_APP_ISOLATION_ENABLED 之后，原本直接挂在
    // /sys/fs/cgroup 下的 uid/任务分组 cgroup 会被重新组织到
    // /sys/fs/cgroup/apps/... 和 /sys/fs/cgroup/system/... 两个父目录下，
    // 具体 top-app 是否/如何被牵连因厂商 ROM 而异，所以这里不再赌一份
    // 写死的路径清单，而是有限深度遍历目录树直接找，找到即返回。
    // max_depth 防止在挂载了大量子目录（如每个 uid 一个目录）的层级
    // 里做无意义的深度扫描浪费时间。
    std::string find_top_app_dir(const std::string& base_dir, int max_depth) {
        if (max_depth <= 0) return "";
        DIR* dir = opendir(base_dir.c_str());
        if (!dir) return "";

        std::string found;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;

            std::string full_path = base_dir + "/" + name;

            // 目录名直接命中
            if (name == "top-app") {
                struct stat st;
                if (stat(full_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    found = full_path;
                    break;
                }
            }

            // 只往看起来是分组目录的地方继续下探（跳过明显的叶子文件，
            // 用 stat 判断是否为目录，cgroupfs 下没有 d_type 时的兜底）
            struct stat st;
            if (stat(full_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                std::string sub = find_top_app_dir(full_path, max_depth - 1);
                if (!sub.empty()) { found = sub; break; }
            }
        }
        closedir(dir);
        return found;
    }

    uint64_t read_top_app_cgroup_id() {
        // 快速检测 cgroup2 是否健康
        static bool v2_healthy = []{
            std::ifstream test("/sys/fs/cgroup/cgroup.controllers");
            return test.is_open();
        }();
        if (!v2_healthy) return 0;  // 静默返回，不影响 fail 计数

        // 第零步：上次遍历发现的新层级路径（如 apps/top-app），
        // 命中就直接用，不用每次都重新走已知路径列表再遍历一次
        if (!discovered_top_app_path_.empty()) {
            uint64_t id = read_cgroup_id_at(discovered_top_app_path_);
            if (id > 0) return id;
            // 路径失效了（比如 cgroup 被重建），清空缓存，走完整流程重新找
            discovered_top_app_path_.clear();
        }

        // 第一步：已知的传统路径，命中即返回（多数设备一次就中，
        // 避免每 30 秒都做一次目录遍历）
        static const char* known_paths[] = {
            "/sys/fs/cgroup/top-app",
            "/sys/fs/cgroup/cpu/top-app",
            "/sys/fs/cgroup/unified/top-app",
            nullptr
        };
        for (int i = 0; known_paths[i] != nullptr; ++i) {
            uint64_t id = read_cgroup_id_at(known_paths[i]);
            if (id > 0) {
                LOG_D(TAG, "Found top-app cgroup.id=" + std::to_string(id) +
                           " at " + std::string(known_paths[i]));
                return id;
            }
        }

        // 第二步：已知路径都没命中，说明可能是新层级结构
        // （如 apps/top-app、system/top-app），有限深度遍历查找
        std::string discovered = find_top_app_dir("/sys/fs/cgroup", 4);
        if (!discovered.empty()) {
            uint64_t id = read_cgroup_id_at(discovered);
            if (id > 0) {
                LOG_I(TAG, "Discovered top-app cgroup at new location: " + discovered +
                           " (cgroup.id=" + std::to_string(id) + ")");
                // 记住这次发现的路径，下次直接读，不用重新遍历整棵树
                discovered_top_app_path_ = discovered;
                return id;
            }
        }
        return 0;
    }

    static int on_event_raw(void *ctx, void *data, size_t /*size*/) {
        auto *self = static_cast<BpfLoader*>(ctx);
        auto *ev   = static_cast<FreezeEvent*>(data);
        if (self->callback_) self->callback_(*ev);
        return 0;
    }

    bpf_object*       obj_                = nullptr;
    ring_buffer*      ring_buf_           = nullptr;
    EventCallback     callback_;
    std::atomic<bool> running_{false};
    std::thread       loop_thread_;
    struct bpf_map    *top_app_map_       = nullptr;
    struct bpf_map    *frozen_cgroup_map_ = nullptr;

    static constexpr int FAIL_WARN_THRESHOLD = 3;
    int consecutive_fail_count_ = 0;

    // 有限深度遍历发现的 top-app cgroup 路径缓存（应对 apps/top-app
    // 这类新层级结构），命中一次后长期复用，避免每次都重新遍历目录树
    std::string discovered_top_app_path_;
};