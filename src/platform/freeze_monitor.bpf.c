// SPDX-License-Identifier: GPL-2.0
// freeze_monitor.bpf.c — 内核侧 eBPF 探针
//
// 设计决策（针对 Android 16 + 5.15 GKI + 骁龙 8 Gen 2）：
//
// 1. 前后台检测：sched_switch tracepoint + top-app cgroup id 对比
//    - top-app cgroup id 由用户态在启动时及周期性写入 top_app_cgroup_id map
//    - sched_switch 拿到 next 进程的 cgroup id，与 top_app_cgroup_id 对比，
//      cgroup 发生切换且跨越 top-app 边界时才发事件（last_cgroup_map 去重）
//    - next 进程的 uid 内核侧无法低成本获取，事件携带 uid=0，
//      由用户态优先查内存中的 uid_pid_map 反查，未命中再读 /proc 兜底
//
// 2. 屏幕事件：suspend_resume tracepoint（内核级，可靠）
//
// 3. PID 追踪：sched_process_fork + sched_process_exit 维护 uid_pid_map
//    - 用户态直接读取该 map 维护的 PidCache，消除 /proc 遍历开销

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── 事件类型（与用户态 constants.h 完全一致）────────────────
#define EVT_APP_FOREGROUND  1
#define EVT_APP_BACKGROUND  2
#define EVT_SCREEN_ON       3
#define EVT_SCREEN_OFF      4
#define EVT_SYS_UNFREEZE    5
#define EVT_PROC_DIED       6

struct freeze_event {
    __u8  type;
    __u32 uid;
    __u32 pid;
};  // 实际内存布局含 padding，对齐到 12 字节（type 后 3 字节 padding）

// ── Maps ─────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// top-app cgroup id（用户态启动时写入，BPF 只读）
// key=0 存储 top-app cgroup id，进程在此 cgroup = 前台
// 由 BpfLoader::load() 后立即写入，并由主循环周期刷新（top-app 切换时该 id 会变化）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} top_app_cgroup_id SEC(".maps");

// 我们管理的已冻结 cgroup id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   __u64);
    __type(value, __u8);
} our_frozen_cgroups SEC(".maps");

// uid → 上次感知到的 cgroup id（检测 cgroup 切换）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   __u32);   // uid
    __type(value, __u64);   // cgroup id
} last_cgroup_map SEC(".maps");

// uid → pid set（用户态读取，消除 /proc 遍历）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key,   __u64);   // (uid << 32) | pid
    __type(value, __u8);    // 1 = 存活
} uid_pid_map SEC(".maps");

// ── 辅助函数 ─────────────────────────────────────────────────

static __always_inline void emit_ev(__u8 type, __u32 uid, __u32 pid) {
    struct freeze_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return;
    out->type = type;
    out->uid  = uid;
    out->pid  = pid;
    bpf_ringbuf_submit(out, 0);
}

// 从 task_struct 读取进程真实 uid（而非用 bpf_get_current_uid_gid，
// 后者只能拿到当前正在执行的 prev task 的 uid，对 sched_switch 的 next 无效）
// 当前实现未实际调用此函数（next task 的 uid 改由用户态反查），保留备用
static __always_inline __u32 get_task_uid(struct task_struct *task) {
    // cred->uid.val 是进程真实 uid
    kuid_t kuid = BPF_CORE_READ(task, cred, uid);
    return kuid.val;
}

// ── sched_switch：检测前后台切换 ─────────────────────────────
// 在调度器切换时，检查 next 进程所属 cgroup 是否变化
// 若从非 top-app 变为 top-app cgroup → 前台事件
// 若从 top-app 变为其他 cgroup → 后台事件
SEC("tracepoint/sched/sched_switch")
int on_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u32 next_pid = ctx->next_pid;
    if (next_pid <= 1) return 0;  // idle/init 跳过

    // next 进程的真实 uid 在 sched_switch 上下文中无法低成本获取
    // （bpf_get_current_uid_gid 拿到的是 prev/当前执行进程，不是 next），
    // 因此用 cgroup_id 来判断前后台切换（不依赖 uid），
    // 事件 uid 字段设为 0，由用户态通过 ev.pid 反查
    // （优先查 PidCache 内存索引，未命中再读 /proc 兜底，见 event_dispatcher.h）

    __u64 cg_id = bpf_get_current_cgroup_id();  // next 进程的 cgroup id

    // 读取 top-app cgroup id（key=0）
    __u32 key = 0;
    __u64 *top_cg = bpf_map_lookup_elem(&top_app_cgroup_id, &key);
    if (!top_cg || *top_cg == 0) return 0;  // 未初始化，跳过

    // 对比上次的 cgroup（用 pid 做 key，避免 uid 未知的问题）
    __u64 pid_key = next_pid;
    __u64 *last_cg = bpf_map_lookup_elem(&last_cgroup_map, &pid_key);

    bool was_top_app = (last_cg && *last_cg == *top_cg);
    bool is_top_app  = (cg_id == *top_cg);

    // cgroup 未变化，忽略
    if (last_cg && *last_cg == cg_id) return 0;

    // 更新记录
    bpf_map_update_elem(&last_cgroup_map, &pid_key, &cg_id, BPF_ANY);

    // 只发送有意义的状态变化
    if (!was_top_app && is_top_app) {
        // 进入前台
        emit_ev(EVT_APP_FOREGROUND, 0, next_pid);  // uid=0，由用户态反查
    } else if (was_top_app && !is_top_app) {
        // 离开前台
        emit_ev(EVT_APP_BACKGROUND, 0, next_pid);
    }
    return 0;
}

// ── sched_process_fork：追踪新进程 uid ───────────────────────
SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 child_pid = ctx->child_pid;
    // parent uid = 当前进程 uid（fork 继承）
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u64 key = ((__u64)uid << 32) | child_pid;
    __u8 val = 1;
    bpf_map_update_elem(&uid_pid_map, &key, &val, BPF_ANY);
    return 0;
}

// ── sched_process_exit：清理退出进程 ─────────────────────────
SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u32 pid = ctx->pid;

    // 从 uid_pid_map 移除
    __u64 key = ((__u64)uid << 32) | pid;
    bpf_map_delete_elem(&uid_pid_map, &key);

    // 清理 last_cgroup_map
    __u64 pid_key = pid;
    bpf_map_delete_elem(&last_cgroup_map, &pid_key);

    emit_ev(EVT_PROC_DIED, uid, pid);
    return 0;
}

// ── suspend_resume：屏幕亮灭 ─────────────────────────────────
// Android 的 suspend/resume 在骁龙 8 Gen 2 上是可靠的内核事件
// 用户态同时监听 /dev/input 作为补充（两者取或，用户态处理去重）
SEC("tracepoint/power/suspend_resume")
int on_suspend_resume(struct trace_event_raw_power_suspend_resume *ctx) {
    __u8 type = ctx->val ? EVT_SCREEN_OFF : EVT_SCREEN_ON;
    emit_ev(type, 0, 0);
    return 0;
}

// ── kprobe/cgroup_freeze：感知系统解冻 ───────────────────────
SEC("kprobe/cgroup_freeze")
int on_cgroup_freeze(struct pt_regs *ctx) {
    struct cgroup *cgrp = (struct cgroup *)PT_REGS_PARM1(ctx);
    bool freeze = (bool)PT_REGS_PARM2(ctx);
    if (freeze) return 0;

    __u64 cg_id = BPF_CORE_READ(cgrp, kn, id);
    __u8 *managed = bpf_map_lookup_elem(&our_frozen_cgroups, &cg_id);
    if (!managed) return 0;

    __u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    emit_ev(EVT_SYS_UNFREEZE, 0, pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
