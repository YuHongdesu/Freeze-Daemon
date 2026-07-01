// SPDX-License-Identifier: GPL-2.0
// freeze_monitor.bpf.c — 内核侧 eBPF 探针 (v3)
//
// 针对 Android 16 + 5.15 GKI + 骁龙 8 Gen 2
//
// 核心逻辑：
// 1. 使用 cgroup_attach_task tracepoint 感知进程进出 top-app cgroup
//    - 从 ctx->dst_id 直接获取目标 cgroup id
//    - 结合 pid->last_cgroup 映射，准确判断前后台切换
//    - pid 对应的 uid 通过 pid_uid_map 查得（由 fork/exit 维护）
// 2. 屏幕事件使用 tp_btf/suspend_resume raw tracepoint（避免 vmlinux.h 兼容问题）
// 3. kprobe/cgroup_freeze 依赖 __TARGET_ARCH_arm64，编译时通过 -D 注入
// 4. uid_pid_map 保留供用户态查询；pid_uid_map 用于内核侧快速反查 uid

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── 事件类型（与用户态 constants.h 一致）────────────────────
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
} __attribute__((packed));

// ── Maps ─────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// top-app cgroup id（用户态写入）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} top_app_cgroup_id SEC(".maps");

// 我们管理的已冻结 cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   __u64);
    __type(value, __u8);
} our_frozen_cgroups SEC(".maps");

// uid → pid 集合（供用户态读取）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key,   __u64);   // (uid << 32) | pid
    __type(value, __u8);
} uid_pid_map SEC(".maps");

// pid → uid 反查（内核侧快速获取 uid）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key,   __u32);   // pid
    __type(value, __u32);   // uid
} pid_uid_map SEC(".maps");

// pid → 上次所在 cgroup id（用于判断前后台切换）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key,   __u32);   // pid
    __type(value, __u64);   // last cgroup id
} pid_cgroup_map SEC(".maps");

// ── 辅助函数 ─────────────────────────────────────────────────

static __always_inline void emit_ev(__u8 type, __u32 uid, __u32 pid) {
    struct freeze_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return;
    out->type = type;
    out->uid  = uid;
    out->pid  = pid;
    bpf_ringbuf_submit(out, 0);
}

// ── cgroup_attach_task：前后台切换检测 ───────────────────────
SEC("tracepoint/cgroup/cgroup_attach_task")
int on_cgroup_attach(struct trace_event_raw_cgroup_attach_task *ctx) {
    __u32 key0 = 0;
    __u64 *top_cg = bpf_map_lookup_elem(&top_app_cgroup_id, &key0);
    if (!top_cg || *top_cg == 0)
        return 0;

    __u64 dst_id = ctx->dst_id;
    __u32 pid = ctx->pid;

    // 查找 uid
    __u32 *uidp = bpf_map_lookup_elem(&pid_uid_map, &pid);
    __u32 uid = uidp ? *uidp : 0;

    // 查找上次 cgroup id
    __u64 *last_cgp = bpf_map_lookup_elem(&pid_cgroup_map, &pid);
    __u64 last_cg = last_cgp ? *last_cgp : 0;

    bool was_top = (last_cg == *top_cg);
    bool is_top  = (dst_id == *top_cg);

    // 更新记录
    bpf_map_update_elem(&pid_cgroup_map, &pid, &dst_id, BPF_ANY);

    if (!was_top && is_top) {
        emit_ev(EVT_APP_FOREGROUND, uid, pid);
    } else if (was_top && !is_top) {
        emit_ev(EVT_APP_BACKGROUND, uid, pid);
    }
    return 0;
}

// ── fork / exit：维护 pid ↔ uid 映射 ────────────────────────

SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 child_pid = ctx->child_pid;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u64 key = ((__u64)uid << 32) | child_pid;
    __u8 val = 1;
    bpf_map_update_elem(&uid_pid_map, &key, &val, BPF_ANY);

    bpf_map_update_elem(&pid_uid_map, &child_pid, &uid, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u32 pid = ctx->pid;

    __u64 key = ((__u64)uid << 32) | pid;
    bpf_map_delete_elem(&uid_pid_map, &key);

    bpf_map_delete_elem(&pid_uid_map, &pid);
    bpf_map_delete_elem(&pid_cgroup_map, &pid);

    emit_ev(EVT_PROC_DIED, uid, pid);
    return 0;
}

// ── suspend_resume：使用 raw tracepoint 避免结构体缺失 ──────
SEC("tp_btf/suspend_resume")
int on_suspend_resume(int val) {
    __u8 type = val ? EVT_SCREEN_OFF : EVT_SCREEN_ON;
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