#pragma once
#include <string>
#include <fstream>
#include <functional>
#include <thread>
#include <atomic>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "util/constants.h"
#include "util/logger.h"

// 事件结构（必须与 freeze_monitor.bpf.c 的 freeze_event 内存布局完全一致）
struct FreezeEvent {
    uint8_t  type;
    uint8_t  _pad[3];
    uint32_t uid;
    uint32_t pid;
};
static_assert(sizeof(FreezeEvent) == 12, "FreezeEvent must match kernel-side freeze_event layout exactly");

using EventCallback = std::function<void(const FreezeEvent&)>;

class BpfLoader {
public:
    static constexpr const char* TAG      = "BpfLoader";
    static constexpr const char* OBJ_PATH = "/data/adb/modules/freeze-daemon/bin/freeze_monitor.bpf.o";

    bool load(EventCallback cb) {
        callback_ = std::move(cb);

        obj_ = bpf_object__open(OBJ_PATH);
        if (!obj_) { LOG_E(TAG, "bpf_object__open failed"); return false; }

        // 在加载前跳过不稳定的钩子（如需要）
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

    // 跳过已知不稳定的程序（可选）
    void skip_unstable_probes() {
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj_) {
            const char *name = bpf_program__name(prog);
            if (strcmp(name, "on_cgroup_migrate") == 0) {
                // 如果内核不支持 tp_btf/cgroup_migrate，跳过该程序
                // 可根据内核版本判断，这里为最大化兼容性一律跳过
                bpf_program__set_autoload(prog, false);
                LOG_W(TAG, "Skipping on_cgroup_migrate (may not be supported)");
            }
        }
    }

    // 逐个尝试 attach，不因单个失败而整体退出
    bool attach_probes_gracefully() {
        struct bpf_program *prog;
        int attached = 0;
        int total = 0;

        bpf_object__for_each_program(prog, obj_) {
            total++;
            // 跳过被设为不自动加载的程序
            if (!bpf_program__autoload(prog)) {
                LOG_I(TAG, "Skipping attach for unloaded program: " + std::string(bpf_program__name(prog)));
                continue;
            }

            struct bpf_link *link = bpf_program__attach(prog);
            if (!link) {
                LOG_W(TAG, std::string("Failed to attach: ") + bpf_program__name(prog) +
                            ", errno: " + std::to_string(errno));
                continue;
            }
            attached++;
            // link 由 libbpf 管理，无需手动释放（随 object 生命周期）
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

    uint64_t read_top_app_cgroup_id() {
        // 尝试多个可能的路径
        static const char* paths[] = {
            "/sys/fs/cgroup/top-app/cgroup.id",
            "/sys/fs/cgroup/cpu/top-app/cgroup.id",
            "/sys/fs/cgroup/unified/top-app/cgroup.id",
            "/dev/cgroup_info/cgroup.controllers",  // 其他可能的线索
            nullptr
        };

        for (int i = 0; paths[i] != nullptr; ++i) {
            std::ifstream f(paths[i]);
            if (!f.is_open()) continue;
            uint64_t id = 0;
            f >> id;
            if (f.fail()) continue;
            // 部分路径可能不是直接可读的数字，可忽略
            if (id > 0) {
                LOG_D(TAG, "Found top-app cgroup.id=" + std::to_string(id) + " at " + paths[i]);
                return id;
            }
        }

        // 通用降级：遍历 /sys/fs/cgroup 下的所有子目录寻找 top-app
        // 这里保持简单，返回 0 表示未找到
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
};