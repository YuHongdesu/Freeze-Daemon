// SPDX-License-Identifier: GPL-2.0
// freeze_monitor.bpf.c — 内核侧 eBPF 探针 (v4-fixed)
//
// 针对 Android 16 + 5.15 GKI + 骁龙 8 Gen 2
//
// 关键修复：
// - on_cgroup_migrate 改用 tp_btf + BPF_PROG，直接获取 tracepoint 参数
// - on_suspend_resume 改用 tp_btf + BPF_PROG，避免验证器报错
// - 前后台切换通过比较 src/dst cgroup id 与 top-app cgroup id 精确判定
// - kprobe/cgroup_freeze 依赖编译选项 __TARGET_ARCH_arm64

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

// 关键修复：必须与用户态 bpf_loader.h 的 FreezeEvent 逐字节一致。
// 之前内核侧标了 __attribute__((packed))（9 字节，uid 在 offset 1），
// 用户态是普通对齐 struct（12 字节，uid 在 offset 4）——ring buffer
// 里的事件被用户态用错误的偏移量解析，读到的 uid/pid 是垃圾值。
// 现在两边都显式 packed + 显式填充 3 字节 pad，编译器默认对齐规则
// 不再参与决定布局，双方永远逐字节一致（12 字节，与用户态 sizeof 断言吻合）。
struct freeze_event {
    __u8  type;
    __u8  _pad[3];
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

// ── 辅助函数 ─────────────────────────────────────────────────

static __always_inline void emit_ev(__u8 type, __u32 uid, __u32 pid) {
    struct freeze_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return;
    out->type = type;
    out->uid  = uid;
    out->pid  = pid;
    bpf_ringbuf_submit(out, 0);
}

// ── cgroup_migrate：前后台切换检测 (tp_btf) ─────────────────
// 使用 BPF_PROG 宏 + SEC("tp_btf/cgroup_migrate")
// 参数顺序：dst_cgrp, src_cgrp, task, threadgroup
SEC("tp_btf/cgroup_migrate")
int BPF_PROG(on_cgroup_migrate,
    struct cgroup *dst_cgrp,
    struct cgroup *src_cgrp,
    struct task_struct *task,
    bool threadgroup)
{
    __u32 key0 = 0;
    __u64 *top_cg = bpf_map_lookup_elem(&top_app_cgroup_id, &key0);
    if (!top_cg || *top_cg == 0)
        return 0;

    __u64 src_id = BPF_CORE_READ(src_cgrp, kn, id);
    __u64 dst_id = BPF_CORE_READ(dst_cgrp, kn, id);

    bool from_top = (src_id == *top_cg);
    bool to_top   = (dst_id == *top_cg);

    // 未跨越 top-app 边界，忽略
    if (from_top == to_top)
        return 0;

    __u32 uid = BPF_CORE_READ(task, cred, uid.val);
    __u32 pid = BPF_CORE_READ(task, pid);

    if (to_top)
        emit_ev(EVT_APP_FOREGROUND, uid, pid);
    else
        emit_ev(EVT_APP_BACKGROUND, uid, pid);

    return 0;
}

// ── fork / exit：维护 uid_pid_map ────────────────────────────

SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 child_pid = ctx->child_pid;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u64 key = ((__u64)uid << 32) | child_pid;
    __u8 val = 1;
    bpf_map_update_elem(&uid_pid_map, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u32 pid = ctx->pid;

    __u64 key = ((__u64)uid << 32) | pid;
    bpf_map_delete_elem(&uid_pid_map, &key);

    emit_ev(EVT_PROC_DIED, uid, pid);
    return 0;
}

// ── suspend_resume：使用 tp_btf + BPF_PROG ─────────────────
// 直接提取 int 参数，避免验证器将 ctx 当标量处理
SEC("tp_btf/suspend_resume")
int BPF_PROG(on_suspend_resume, int val) {
    __u8 type = val ? EVT_SCREEN_OFF : EVT_SCREEN_ON;
    emit_ev(type, 0, 0);
    return 0;
}

// ── kprobe/cgroup_freeze：感知系统解冻 ───────────────────────
// 依赖编译时 -D__TARGET_ARCH_arm64
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