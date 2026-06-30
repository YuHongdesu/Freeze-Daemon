#pragma once
#include <string>
#include <fstream>
#include <functional>
#include <thread>
#include <atomic>
#include <bpf/libbpf.h>
#include "util/constants.h"
#include "util/logger.h"

// 事件结构（必须与 freeze_monitor.bpf.c 的 freeze_event 内存布局完全一致）
// 严重 Bug 修复：原结构体多了 comm[16] 字段，但内核侧从未填充，
// ring_buffer 回调中的 reinterpret 会越界读取 16 字节脏内存。
// 内核结构体 {u8 type; u32 uid; u32 pid;} 实际对齐后为 12 字节
// （type 后有 3 字节 padding，凑齐 uid 的 4 字节对齐）
struct FreezeEvent {
    uint8_t  type;
    uint8_t  _pad[3];   // 显式声明 padding，避免编译器差异导致的隐式布局不一致
    uint32_t uid;
    uint32_t pid;
};
static_assert(sizeof(FreezeEvent) == 12, "FreezeEvent must match kernel-side freeze_event layout exactly");

using EventCallback = std::function<void(const FreezeEvent&)>;

// 平台层：eBPF 加载与事件读取，不含任何业务逻辑
class BpfLoader {
public:
    static constexpr const char* TAG      = "BpfLoader";
    static constexpr const char* OBJ_PATH = "/data/adb/modules/freeze-daemon/bin/freeze_monitor.bpf.o";

    bool load(EventCallback cb) {
        callback_ = std::move(cb);

        obj_ = bpf_object__open(OBJ_PATH);
        if (!obj_) { LOG_E(TAG, "bpf_object__open failed"); return false; }

        if (bpf_object__load(obj_)) { LOG_E(TAG, "bpf_object__load failed"); return false; }

        if (!attach_probes()) return false;

        ring_buf_ = setup_ringbuf();
        if (!ring_buf_) return false;

        // 提取 map fd，供 set_top_app_cgroup / our_frozen_cgroups 写入使用
        top_app_map_fd_   = find_map_fd("top_app_cgroup_id");
        frozen_cgroup_fd_ = find_map_fd("our_frozen_cgroups");
        if (top_app_map_fd_ < 0)   LOG_W(TAG, "top_app_cgroup_id map not found");
        if (frozen_cgroup_fd_ < 0) LOG_W(TAG, "our_frozen_cgroups map not found");

        // 首次写入当前 top-app cgroup id，否则 sched_switch 探针完全不工作
        refresh_top_app_cgroup();

        LOG_I(TAG, "eBPF loaded and attached");
        return true;
    }

    // top-app 切换设备时其 cgroup id 也会变化（系统会重新挂载/创建新 cgroup），
    // 需要周期性刷新，否则前后台检测会在某次切换后失效
    // 返回值：是否成功写入（fd 不存在或读取失败时返回 false）
    bool refresh_top_app_cgroup() {
        if (top_app_map_fd_ < 0) return false;

        uint64_t cg_id = read_top_app_cgroup_id();
        if (cg_id == 0) {
            // 单次失败可能只是瞬时（top-app 正在切换中），不立即告警
            // 连续失败达到阈值才升级为 WARN，避免日志刷屏又能反映持续性问题
            if (++consecutive_fail_count_ >= FAIL_WARN_THRESHOLD) {
                LOG_W(TAG, "top-app cgroup.id read failed " +
                           std::to_string(consecutive_fail_count_) +
                           " times in a row, foreground detection may be stale");
            }
            return false;
        }
        consecutive_fail_count_ = 0;

        uint32_t key = 0;
        int ret = bpf_map_update_elem(top_app_map_fd_, &key, &cg_id, BPF_ANY);
        if (ret != 0) {
            LOG_W(TAG, "Failed to update top_app_cgroup_id");
            return false;
        }
        return true;
    }

    // 暴露连续失败次数，供上层（main.cpp 的调度逻辑）决定是否需要
    // 启用 shell 兜底检测。BpfLoader 本身是纯平台层，不直接依赖
    // core 层的 FreezeEngine，决策权交给调用方
    int consecutive_fail_count() const { return consecutive_fail_count_; }

    int frozen_cgroup_map_fd() const { return frozen_cgroup_fd_; }

    // 在后台线程启动事件循环
    void start_loop() {
        running_ = true;
        loop_thread_ = std::thread(&BpfLoader::poll_loop, this);
    }

    // 等待事件循环退出（主线程阻塞于此，由信号触发 stop() 后返回）
    void join() {
        if (loop_thread_.joinable()) loop_thread_.join();
    }

    void stop() {
        running_ = false;          // 先置标志，让 poll_loop 退出
        if (loop_thread_.joinable()) loop_thread_.join();  // 等线程退出
        if (ring_buf_) { ring_buffer__free(ring_buf_); ring_buf_ = nullptr; }
        if (obj_)      { bpf_object__close(obj_);      obj_      = nullptr; }
    }

private:
    void poll_loop() {
        while (running_) {
            ring_buffer__poll(ring_buf_, /* timeout_ms= */ 200);
        }
    }

private:
    bool attach_probes() {
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj_) {
            struct bpf_link *link = bpf_program__attach(prog);
            if (!link) {
                LOG_E(TAG, std::string("Failed to attach: ") + bpf_program__name(prog));
                return false;
            }
        }
        return true;
    }

    ring_buffer* setup_ringbuf() {
        struct bpf_map *map = bpf_object__find_map_by_name(obj_, "events");
        if (!map) { LOG_E(TAG, "Cannot find events map"); return nullptr; }

        int fd = bpf_map__fd(map);
        return ring_buffer__new(fd, on_event_raw, this, nullptr);
    }

    int find_map_fd(const char* name) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj_, name);
        return map ? bpf_map__fd(map) : -1;
    }

    // 读取系统当前 top-app cgroup 的 id
    // top-app 进程统一被 ActivityManager 放入 /sys/fs/cgroup/top-app/ 子组
    // 读其 cgroup.id 文件即可，不需要 root shell 调用
    uint64_t read_top_app_cgroup_id() {
        std::ifstream f("/sys/fs/cgroup/top-app/cgroup.id");
        if (!f.is_open()) return 0;
        uint64_t id = 0;
        f >> id;
        return id;
    }

    // libbpf 回调，转发给业务回调
    static int on_event_raw(void *ctx, void *data, size_t /*size*/) {
        auto *self = static_cast<BpfLoader*>(ctx);
        auto *ev   = static_cast<FreezeEvent*>(data);
        if (self->callback_) self->callback_(*ev);
        return 0;
    }

    bpf_object*       obj_              = nullptr;
    ring_buffer*      ring_buf_         = nullptr;
    EventCallback     callback_;
    std::atomic<bool> running_{false};
    std::thread       loop_thread_;
    int               top_app_map_fd_   = -1;
    int               frozen_cgroup_fd_ = -1;

    // top-app cgroup 读取失败的连续计数，达到阈值才升级日志级别
    static constexpr int FAIL_WARN_THRESHOLD = 3;
    int consecutive_fail_count_ = 0;
};
