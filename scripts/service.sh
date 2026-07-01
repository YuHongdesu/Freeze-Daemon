#!/system/bin/sh
# service.sh — 层 A：静态管控层
# 职责：开机一次性初始化，处理系统应用黑名单，剥夺非白名单用户 app AppOp
# 重要：关闭系统 Freezer，由 Daemon 独立接管，避免 cgroup 冲突

MODDIR="${0%/*}"
CONFIG_DIR="$MODDIR/config"
SYS_BLACKLIST="$CONFIG_DIR/system_blacklist.txt"
USER_WHITELIST="$CONFIG_DIR/user_whitelist.txt"
LOG_FILE="$MODDIR/logs/service.log"

# ── 工具函数 ──────────────────────────────────────────────

log() { echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE"; }

wait_boot_complete() {
    until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
    sleep 5
    log "Boot completed"
}

# ── 关闭系统 Freezer，由 Daemon 独立接管 ─────────────────
# 系统 Freezer 使用 uid_N cgroup，会把进程迁出我们的 cgroup 子树
# 导致 cgroup.freeze=1 失效，触发大量 bounce，因此必须关闭
#
# 注意：device_config 写入不保证不被后续系统服务覆盖，
# 持续性的重新检查由 freeze_daemon 内部的周期定时器负责
# （见 freeze_engine.h 的 start_freezer_guard），
# 这里只做开机时的首次设置，不在 shell 脚本里做阻塞循环
disable_system_freezer() {
    device_config put activity_manager_native_boot use_freezer false
    settings put global cached_apps_freezer disabled 2>/dev/null
    device_config put activity_manager use_compaction true
    log "System freezer disabled (initial), periodic guard runs in Daemon"
}

# ── AppOp 剥夺列表：从共享配置文件读取（唯一数据源）──────────
# 与 src/platform/appop_manager.h 的 RESTRICT_OPS 数组保持同一份数据，
# 避免 C++ 头文件和 shell 脚本各自维护一份列表导致修改时遗漏同步
APPOP_LIST_FILE="$CONFIG_DIR/appop_restrict_list.txt"

load_restrict_ops() {
    if [ -f "$APPOP_LIST_FILE" ]; then
        RESTRICT_OPS=$(grep -v '^#' "$APPOP_LIST_FILE" | grep -v '^$')
    else
        log "appop_restrict_list.txt not found, using fallback"
        RESTRICT_OPS="RUN_IN_BACKGROUND
RUN_ANY_IN_BACKGROUND
WAKE_LOCK"
    fi
}

revoke_appops() {
    local pkg="$1"
    echo "$RESTRICT_OPS" | while IFS= read -r op; do
        [ -z "$op" ] && continue
        cmd appops set "$pkg" "$op" deny 2>/dev/null
    done
}

restore_appops() {
    local pkg="$1"
    echo "$RESTRICT_OPS" | while IFS= read -r op; do
        [ -z "$op" ] && continue
        cmd appops set "$pkg" "$op" default 2>/dev/null
    done
}

# ── 系统应用黑名单处理 ────────────────────────────────────

apply_sys_blacklist_entry() {
    local pkg="$1"
    cmd deviceidle whitelist "-$pkg" 2>/dev/null
    revoke_appops "$pkg"
    log "System blacklisted: $pkg"
}

apply_system_blacklist() {
    [ ! -f "$SYS_BLACKLIST" ] && return
    local count=0
    while IFS= read -r pkg; do
        case "$pkg" in '#'*|'') continue ;; esac
        apply_sys_blacklist_entry "$pkg"
        count=$((count + 1))
    done < "$SYS_BLACKLIST"
    log "System blacklist applied: $count packages"
}

# ── 用户应用 AppOp 剥夺（白名单除外）────────────────────────

is_in_whitelist() {
    local pkg="$1"
    [ ! -f "$USER_WHITELIST" ] && return 1
    grep -qxF "$pkg" "$USER_WHITELIST" 2>/dev/null
}

apply_user_appop_restrictions() {
    log "Applying user app AppOp restrictions..."
    local count=0 skipped=0
    pm list packages -U 2>/dev/null | while IFS= read -r line; do
        pkg=$(echo "$line" | sed 's/package:\(.*\) uid:.*/\1/')
        uid=$(echo "$line" | sed 's/.*uid:\([0-9]*\).*/\1/')
        [ -z "$pkg" ] || [ -z "$uid" ] && continue
        [ "$uid" -lt 10000 ] 2>/dev/null && continue
        if is_in_whitelist "$pkg"; then
            restore_appops "$pkg"
            skipped=$((skipped + 1))
        else
            revoke_appops "$pkg"
            count=$((count + 1))
        fi
    done
    log "User AppOp restrictions done"
}

# ── 目录初始化 ────────────────────────────────────────────

init_dirs() {
    mkdir -p "$MODDIR/logs"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$MODDIR/tmp"
}

# ── 动态层启动 ────────────────────────────────────────────

start_daemon() {
    local daemon="$MODDIR/bin/freeze_daemon"
    # 确保二进制可执行（zip 解压可能丢失执行权限）
    chmod 755 "$daemon" 2>/dev/null
    [ ! -x "$daemon" ] && { log "freeze_daemon not found"; return; }
    pkill -f freeze_daemon 2>/dev/null
    sleep 1
    "$daemon" >> "$LOG_FILE" 2>&1 &
    log "freeze_daemon started (PID=$!)"
}

# ── 主流程 ────────────────────────────────────────────────

main() {
    init_dirs
    wait_boot_complete
    load_restrict_ops
    disable_system_freezer
    apply_system_blacklist
    apply_user_appop_restrictions
    start_daemon
}

main