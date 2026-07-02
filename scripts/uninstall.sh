#!/system/bin/sh
# uninstall.sh — 卸载清理脚本
#
# KernelSU 卸载模块时会立即删除模块目录本身（/data/adb/modules/<id>），
# 但这只清理"模块目录内"的东西。这个模块运行期间在模块目录之外动过
# 几类系统状态，这些不会随目录删除自动消失，必须在这里手动撤销：
#   1. /sys/fs/cgroup/freeze_daemon 独立 cgroup 子树（cgroupfs 是独立
#      的虚拟文件系统，与 /data/adb/modules 无关）
#   2. 被剥夺的 AppOps 权限（cmd appops，Android 框架层状态）
#   3. 被踢出 Doze 白名单的系统黑名单应用（cmd deviceidle）
#   4. 被关闭的系统原生 Freezer 开关（device_config / settings，全局设置）
#
# 注意：本脚本依赖 config/ 下的名单文件（system_blacklist.txt、
# user_whitelist.txt）来确定"当初剥夺过哪些应用的 AppOps"，这些文件
# 此刻应该还在模块目录里（脚本自己也在这个目录里，执行到这里说明
# 目录内容此刻还没被清空）。为防止极端情况下名单文件已经不可读，
# 每一步都做了存在性检查，读不到就跳过对应清理而不是让整个脚本中断——
# 优先保证 cgroup 清理这个最关键的部分一定能跑完。

MODDIR="${0%/*}"
CONFIG_DIR="$MODDIR/config"
SYS_BLACKLIST="$CONFIG_DIR/system_blacklist.txt"
USER_WHITELIST="$CONFIG_DIR/user_whitelist.txt"
APPOP_LIST_FILE="$CONFIG_DIR/appop_restrict_list.txt"

CGROUP_ROOT="/sys/fs/cgroup/freeze_daemon"
CGROUP_FROZEN="$CGROUP_ROOT/frozen"
CGROUP_ACTIVE="$CGROUP_ROOT/active"

# uninstall.sh 没有独立日志文件（此刻 logs/ 目录本身也即将被删），
# 直接输出到 stdout，KernelSU 会把这些输出收进它自己的操作日志里
log() { echo "[freeze-daemon uninstall] $1"; }

# ── 第一步：停止正在运行的 daemon 进程 ──────────────────────
# 必须先做这一步，否则 daemon 可能在我们清理 cgroup 的同时又把进程
# 迁移回去，或者在我们恢复 AppOps 之后又剥夺一次，产生竞态
stop_daemon() {
    if pgrep -f freeze_daemon >/dev/null 2>&1; then
        log "Stopping freeze_daemon..."
        pkill -TERM -f freeze_daemon 2>/dev/null
        # 给它一点时间优雅退出（它的信号处理里会做 unlink pid 文件等清理）
        local waited=0
        while pgrep -f freeze_daemon >/dev/null 2>&1 && [ "$waited" -lt 5 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        # 5 秒后还没退出，直接 SIGKILL，不能让卸载流程被一个卡住的进程拖死
        if pgrep -f freeze_daemon >/dev/null 2>&1; then
            log "freeze_daemon did not exit gracefully, force killing"
            pkill -KILL -f freeze_daemon 2>/dev/null
        fi
    fi
}

# ── 第二步：清理独立 cgroup 子树 ────────────────────────────
# cgroup v2 的目录必须先清空（无进程、无子目录）才能 rmdir，顺序是：
#   1. 解冻 frozen 子组（cgroup.freeze 写 0），否则里面的进程会一直
#      卡在 D 状态/冻结态，把它们的 pid 挪出来时可能因为还在冻结而失败
#   2. 把 frozen、active 两个子组里所有 pid 挪回 cgroup 根节点
#      （直接写 /sys/fs/cgroup/cgroup.procs 是 cgroup v2 里"移到根"
#      的标准写法）
#   3. 先 rmdir 子目录（frozen、active），再 rmdir 父目录（root）——
#      cgroup v2 和普通目录一样，非空目录 rmdir 会失败，必须先子后父
cleanup_cgroup() {
    if [ ! -d "$CGROUP_ROOT" ]; then
        log "cgroup subtree not present, nothing to clean"
        return
    fi

    log "Cleaning up cgroup subtree: $CGROUP_ROOT"

    # 解冻，确保没有进程被永久卡住
    if [ -f "$CGROUP_FROZEN/cgroup.freeze" ]; then
        echo 0 > "$CGROUP_FROZEN/cgroup.freeze" 2>/dev/null
    fi

    # 把两个子组里的 pid 全部挪回根 cgroup
    for sub in "$CGROUP_FROZEN" "$CGROUP_ACTIVE"; do
        if [ -f "$sub/cgroup.procs" ]; then
            # cgroup.procs 一次只能读到当时的快照，进程可能在读取过程中
            # 有变化，循环几次尽量挪干净；挪不干净也不阻塞后续 rmdir 尝试
            local attempt=0
            while [ -s "$sub/cgroup.procs" ] && [ "$attempt" -lt 3 ]; do
                while IFS= read -r pid; do
                    [ -z "$pid" ] && continue
                    echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null
                done < "$sub/cgroup.procs"
                attempt=$((attempt + 1))
            done
        fi
    done

    # 先子后父。如果某个目录因为还有残留进程而删不掉，不让脚本因此
    # 中断——记录下来，剩余部分（AppOps 恢复等）仍然继续执行
    rmdir "$CGROUP_FROZEN" 2>/dev/null
    rmdir "$CGROUP_ACTIVE" 2>/dev/null
    if rmdir "$CGROUP_ROOT" 2>/dev/null; then
        log "cgroup subtree removed"
    else
        log "WARNING: cgroup subtree not fully removed (some pids may remain assigned); it will be harmless but orphaned until next reboot"
    fi
}

# ── 第三步：恢复 AppOps 和 Doze 白名单 ──────────────────────
# 与 service.sh 的 revoke_appops 完全对称：用同一份 op 列表，
# 对同一批当初被剥夺过的应用，执行相反操作（deny → default）
load_restrict_ops() {
    if [ -f "$APPOP_LIST_FILE" ]; then
        RESTRICT_OPS=$(grep -v '^#' "$APPOP_LIST_FILE" | grep -v '^$')
    else
        RESTRICT_OPS="RUN_IN_BACKGROUND
RUN_ANY_IN_BACKGROUND
WAKE_LOCK"
    fi
}

restore_appops_for_pkg() {
    local pkg="$1"
    echo "$RESTRICT_OPS" | while IFS= read -r op; do
        [ -z "$op" ] && continue
        cmd appops set "$pkg" "$op" default 2>/dev/null
    done
}

is_in_whitelist() {
    local pkg="$1"
    [ ! -f "$USER_WHITELIST" ] && return 1
    grep -qxF "$pkg" "$USER_WHITELIST" 2>/dev/null
}

restore_user_appops() {
    log "Restoring AppOps for user apps..."
    local count=0
    # 与 service.sh 的 apply_user_appop_restrictions 遍历同一个集合：
    # 所有 uid>=10000 的已安装应用里，"当初不在白名单"的那些
    # （在白名单里的应用当初就没被剥夺过，不需要恢复）
    pm list packages -U 2>/dev/null | while IFS= read -r line; do
        pkg=$(echo "$line" | sed 's/package:\(.*\) uid:.*/\1/')
        uid=$(echo "$line" | sed 's/.*uid:\([0-9]*\).*/\1/')
        [ -z "$pkg" ] || [ -z "$uid" ] && continue
        [ "$uid" -lt 10000 ] 2>/dev/null && continue
        if is_in_whitelist "$pkg"; then
            continue
        fi
        restore_appops_for_pkg "$pkg"
        count=$((count + 1))
    done
    log "User AppOps restoration done"
}

restore_system_blacklist() {
    [ ! -f "$SYS_BLACKLIST" ] && { log "system_blacklist.txt not found, skipping"; return; }
    log "Restoring system blacklist apps..."
    local count=0
    while IFS= read -r pkg; do
        case "$pkg" in '#'*|'') continue ;; esac
        cmd deviceidle whitelist "+$pkg" 2>/dev/null
        restore_appops_for_pkg "$pkg"
        count=$((count + 1))
    done < "$SYS_BLACKLIST"
    log "System blacklist restored: $count packages"
}

# ── 第四步：恢复系统原生 Freezer 开关 ───────────────────────
# 这两个是全局设置，与具体应用无关，直接改回系统默认值
restore_system_freezer() {
    log "Re-enabling native system freezer..."
    device_config put activity_manager_native_boot use_freezer true 2>/dev/null
    settings put global cached_apps_freezer enabled 2>/dev/null
    # activity_manager use_compaction 是内存压缩开关，与 Freezer 无关，
    # 不属于本模块需要撤销的"系统状态改动"，保留不动
}

# ── 主流程 ────────────────────────────────────────────────
main() {
    log "Starting cleanup for freeze-daemon..."
    stop_daemon
    cleanup_cgroup
    load_restrict_ops
    restore_system_blacklist
    restore_user_appops
    restore_system_freezer
    log "Cleanup complete"
}

main
