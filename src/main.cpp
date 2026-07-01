// freeze_daemon — 主入口
#include <csignal>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <atomic>
#include "util/constants.h"
#include "util/logger.h"
#include "util/timer.h"
#include "util/reboot_flag.h"
#include "core/config_store.h"
#include "core/app_list.h"
#include "core/app_label_cache.h"
#include "core/freeze_engine.h"
#include "platform/cgroup_manager.h"
#include "platform/bpf_loader.h"
#include "platform/foreground_fallback.h"
#include "api/event_dispatcher.h"
#include "api/http_server.h"

constexpr const char* TAG = "Main";
static std::atomic<bool> g_running{true};
static void on_signal(int) { g_running = false; }

static void register_signals() {
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);
    signal(SIGPIPE, SIG_IGN);
}

static void write_pid_file() {
    std::ofstream f(Path::PID_FILE);
    if (f.is_open()) f << getpid();
}
static void remove_pid_file() { ::unlink(Path::PID_FILE); }

static bool init_cgroup() {
    if (!CgroupManager::init_cgroup_tree()) {
        LOG_E(TAG, "Cgroup init failed");
        return false;
    }
    return true;
}

static bool init_bpf(BpfLoader& loader, EventDispatcher& dispatcher) {
    bool ok = loader.load([&](const FreezeEvent& ev) { dispatcher.dispatch(ev); });
    if (!ok) LOG_W(TAG, "eBPF load failed, daemon will run without BPF events");
    return ok;
}

static void init_lists(EventDispatcher& dispatcher) {
    AppList::instance().reload();
    dispatcher.refresh_uid_cache();
}

// 核心：通过 shell 轮询维持前后台状态，并驱动冻结引擎
static void schedule_top_app_refresh(BpfLoader& loader) {
    constexpr int REFRESH_INTERVAL_MS = 30000;

    struct SharedState { std::string last_foreground; };
    auto state = std::make_shared<SharedState>();

    auto refresh_fn = std::make_shared<std::function<void()>>();
    *refresh_fn = [&loader, state, refresh_fn]() {
        loader.refresh_top_app_cgroup();   // 尝试 eBPF 刷新
        std::string cur = ForegroundFallback::detect_foreground_package();
        if (cur.empty()) {
            TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
            return;
        }

        if (cur != state->last_foreground && !state->last_foreground.empty()) {
            LOG_I(TAG, "App switched to background: " + state->last_foreground);
            FreezeEngine::instance().on_app_background(state->last_foreground);
        }
        if (cur != state->last_foreground) {
            LOG_I(TAG, "App switched to foreground: " + cur);
            FreezeEngine::instance().on_app_foreground(cur);
            state->last_foreground = cur;
        } else {
            // 前台未变，但保持 RunningCache 中有该应用
            FreezeEngine::instance().on_app_foreground(cur);
        }

        TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
    };
    (*refresh_fn)();
}

int main() {
    register_signals();
    write_pid_file();

    LOG_I(TAG, "freeze_daemon starting");
    RebootFlag::clear_all();

    ConfigStore::instance().load();
    if (!init_cgroup()) return 1;

    // 构建应用标签缓存（启动 HTTP 前）
    AppLabelCache::instance().build();

    TimerManager::instance().start();

    BpfLoader       bpf_loader;
    EventDispatcher dispatcher;
    bool bpf_ok = init_bpf(bpf_loader, dispatcher);
    if (bpf_ok) {
        FreezeEngine::instance().set_frozen_cgroups_map(bpf_loader.frozen_cgroup_map());
    }

    // 启动前台检测调度
    schedule_top_app_refresh(bpf_loader);

    init_lists(dispatcher);
    FreezeEngine::instance().start_freezer_guard();

    HttpServer http;
    if (!http.start()) return 1;

    LOG_I(TAG, "Running. PID=" + std::to_string(getpid()));
    if (bpf_ok) bpf_loader.start_loop();

    while (g_running) { pause(); }

    LOG_I(TAG, "Shutting down");
    if (bpf_ok) bpf_loader.stop();
    http.stop();
    TimerManager::instance().stop();
    remove_pid_file();
    return 0;
}