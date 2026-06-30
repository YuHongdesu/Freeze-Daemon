// freeze_daemon — 主入口
// 职责：初始化各层，连接事件管道，阻塞运行

#include <csignal>
#include <fstream>
#include <functional>
#include <memory>
#include <unistd.h>
#include "util/constants.h"
#include "util/logger.h"
#include "util/timer.h"
#include "util/reboot_flag.h"
#include "core/config_store.h"
#include "core/app_list.h"
#include "core/freeze_engine.h"
#include "platform/cgroup_manager.h"
#include "platform/bpf_loader.h"
#include "platform/foreground_fallback.h"
#include "api/event_dispatcher.h"
#include "api/http_server.h"

constexpr const char* TAG = "Main";

// ── 信号处理 ─────────────────────────────────────────────

static volatile bool g_running = true;

static void on_signal(int /*sig*/) { g_running = false; }

static void register_signals() {
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);
    signal(SIGPIPE, SIG_IGN);
}

// ── PID 文件 ─────────────────────────────────────────────

static void write_pid_file() {
    std::ofstream f(Path::PID_FILE);
    if (f.is_open()) f << getpid();
}

static void remove_pid_file() {
    ::unlink(Path::PID_FILE);
}

// ── 初始化序列 ────────────────────────────────────────────

static bool init_cgroup() {
    if (!CgroupManager::init_cgroup_tree()) {
        LOG_E(TAG, "Cgroup init failed");
        return false;
    }
    return true;
}

static bool init_bpf(BpfLoader& loader, EventDispatcher& dispatcher) {
    bool ok = loader.load([&dispatcher](const FreezeEvent& ev) {
        dispatcher.dispatch(ev);
    });
    if (!ok) {
        LOG_E(TAG, "eBPF load failed, daemon cannot start");
        return false;
    }
    return true;
}

static void init_lists(EventDispatcher& dispatcher) {
    AppList::instance().reload();
    dispatcher.refresh_uid_cache();
}

// top-app cgroup id 会随系统重新分配而变化（设备重启 top-app 服务、
// 系统资源回收等场景），周期刷新避免 sched_switch 探针逐渐失效
//
// 同时承担 eBPF 失效时的 shell 兜底职责：借鉴 Frosty get_fg_pkg() 的
// 双层 dumpsys 查询模式（见 ForegroundFallback），当 eBPF 连续多次
// 无法读取 top-app cgroup.id 时，主动查询一次当前前台包名并手动
// 驱动一次 on_app_foreground，确保冻结策略不会因为 eBPF 异常而完全失明
static void schedule_top_app_refresh(BpfLoader& loader) {
    constexpr int REFRESH_INTERVAL_MS = 30000;  // 30 秒一次，足够及时且开销极小
    // eBPF 连续失败超过这个次数（约 1.5 分钟）才触发 shell 兜底，
    // 避免瞬时抖动就频繁触发额外的 dumpsys 调用
    constexpr int FALLBACK_TRIGGER_COUNT = 3;

    // 用 shared_ptr 包装自引用闭包，避免局部 lambda 在函数返回后悬空
    auto refresh_fn = std::make_shared<std::function<void()>>();
    *refresh_fn = [&loader, refresh_fn, REFRESH_INTERVAL_MS]() {
        bool ok = loader.refresh_top_app_cgroup();

        if (!ok && loader.consecutive_fail_count() >= FALLBACK_TRIGGER_COUNT) {
            std::string pkg = ForegroundFallback::detect_foreground_package();
            if (!pkg.empty()) {
                LOG_W("Main", "eBPF top-app detection degraded, shell fallback resolved: " + pkg);
                FreezeEngine::instance().on_app_foreground(pkg);
            }
        }

        TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
    };
    (*refresh_fn)();
}

// ── 主函数 ────────────────────────────────────────────────

int main() {
    register_signals();
    write_pid_file();

    LOG_I(TAG, "freeze_daemon starting");

    // Daemon 重启意味着 service.sh 也重新执行过了（KernelSU 每次开机都跑），
    // 之前标记的"待生效"变更（如系统黑名单）现在已经真正生效，清除标记
    RebootFlag::clear_all();

    // 1. 加载配置
    ConfigStore::instance().load();

    // 2. 初始化 cgroup 子树
    if (!init_cgroup()) return 1;

    // 3. 启动定时器线程
    TimerManager::instance().start();

    // 4. 加载 eBPF + 绑定事件回调
    BpfLoader       bpf_loader;
    EventDispatcher dispatcher;
    if (!init_bpf(bpf_loader, dispatcher)) return 1;

    // 4.5 注入 our_frozen_cgroups map fd，供 FreezeEngine 冻结/解冻时写入
    FreezeEngine::instance().set_frozen_cgroups_map_fd(bpf_loader.frozen_cgroup_map_fd());

    // 4.6 周期刷新 top_app_cgroup_id（top-app 切换设备时该 cgroup id 会变化，
    //     不刷新会导致 sched_switch 探针的前后台判断逐渐失效）
    schedule_top_app_refresh(bpf_loader);

    // 5. 加载名单 + 刷新 uid 缓存
    init_lists(dispatcher);

    // 5.5 启动系统 Freezer 防御层（周期检查 device_config 是否被外部重置）
    FreezeEngine::instance().start_freezer_guard();

    // 6. 启动 HTTP API
    HttpServer http;
    if (!http.start()) return 1;

    // 7. 启动 eBPF 后台事件循环，主线程等待信号
    LOG_I(TAG, "Running. PID=" + std::to_string(getpid()));
    bpf_loader.start_loop();

    // 阻塞直到 SIGTERM / SIGINT
    while (g_running) { pause(); }

    // ── 清理 ─────────────────────────────────────────────
    LOG_I(TAG, "Shutting down");
    bpf_loader.stop();      // 先停 eBPF（置 running_=false 并 join 线程）
    http.stop();
    TimerManager::instance().stop();
    remove_pid_file();
    return 0;
}
