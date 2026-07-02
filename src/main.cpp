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

// 关键修复：这个函数原来无条件地每 30 秒调用一次
// FreezeEngine::instance().on_app_foreground/on_app_background，与 eBPF
// 事件路径（EventDispatcher::dispatch）完全并行、互不知晓，且直接绕过了
// RunningCache 的维护逻辑（RunningCache::add 只在
// EventDispatcher::on_foreground 里发生）。
//
// 如果 eBPF 因为某种原因实际没有在产出前后台事件（哪怕 BpfLoader::load()
// 本身返回了成功——例如 top-app cgroup 一直没找到，cgroup_migrate 探针
// 每次都在 *top_cg==0 处提前返回，从不 emit_ev），后台应用就永远不会被
// 加进 RunningCache，息屏时 freeze_all_managed() 就找不到任何要冻结的
// 应用，冻结功能形同虚设——这正是这次要修的核心问题之一。
//
// 现在改成真正的"降级安全网"：
//   1. 每 30 秒总会刷新一次 top-app cgroup id（这本身是良性的必要维护，
//      不管 eBPF 健不健康都该做，成本很低）。
//   2. 只有当 EventDispatcher 最近一段时间确实没有收到过任何 eBPF 事件
//      （dispatcher.last_ebpf_event_age_ms() 超过阈值，或者 eBPF 从
//      一开始就没加载成功）时，才真正把这一轮 shell 检测到的前后台切换
//      喂给 EventDispatcher 的公开入口（notify_foreground/
//      notify_background），走和 eBPF 完全相同的一条代码路径，
//      RunningCache 因此总能被正确维护，不管当前是谁在驱动。
//   3. eBPF 健康时，彻底不参与前后台判定，避免竞态和多余噪音。
//
// 局限性（如实告知，而非过度承诺）：shell 轮询本身没有"进程退出"信号，
// dumpsys activity top 只能看到当前最上层的 Activity，无法感知一个
// 应用退到后台后是否已经被系统杀死。也就是说，如果 eBPF 完全不可用、
// daemon 长期只靠这条 fallback 运行，RunningCache 里的条目在对应进程
// 真正退出后可能不会被及时清理（只有在它重新回到前台再切走、或者
// 下一次 eBPF 恢复健康产生 PROC_DIED 事件时才会被处理）。这是纯 shell
// 轮询这种降级模式本身的能力边界，不是这次改动引入的新问题；日志里会
// 明确提示当前处于降级模式，方便判断是否需要优先解决 eBPF 侧的问题
// （例如本次一并修复的 top-app cgroup 路径发现逻辑）。
static void schedule_top_app_refresh(BpfLoader& loader, EventDispatcher& dispatcher, bool bpf_ok) {
    constexpr int REFRESH_INTERVAL_MS       = 30000;
    // eBPF 事件路径正常工作时，前后台切换应该是毫秒级触发的；给 90 秒
    // 的容忍窗口（相当于 3 个刷新周期都没等到任何事件）才判定为"不健康"，
    // 避免用户长时间停留在同一个应用、eBPF 恰好也没有其他事件
    // （如屏幕开关）时被误判为异常。
    constexpr int64_t EBPF_STALE_THRESHOLD_MS = 90000;

    struct SharedState { std::string last_foreground; bool warned_degraded = false; };
    auto state = std::make_shared<SharedState>();

    auto refresh_fn = std::make_shared<std::function<void()>>();
    *refresh_fn = [&loader, &dispatcher, bpf_ok, state, refresh_fn]() {
        loader.refresh_top_app_cgroup();   // 良性维护动作，始终执行

        bool ebpf_looks_healthy = bpf_ok &&
            (dispatcher.last_ebpf_event_age_ms() < EBPF_STALE_THRESHOLD_MS);

        if (ebpf_looks_healthy) {
            // eBPF 在正常工作，交给它驱动，这里不重复判定前后台，
            // 只需要保持定时刷新继续跑，以便 eBPF 一旦失联能被侦测到
            state->warned_degraded = false;
            TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
            return;
        }

        if (!state->warned_degraded) {
            LOG_W(TAG, "eBPF foreground events stale/unavailable, "
                       "falling back to shell polling for foreground detection "
                       "(degraded mode: cannot detect process death, "
                       "RunningCache entries may not be cleaned up promptly)");
            state->warned_degraded = true;
        }

        std::string cur = ForegroundFallback::detect_foreground_package();
        if (cur.empty()) {
            TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
            return;
        }

        if (cur != state->last_foreground && !state->last_foreground.empty()) {
            LOG_I(TAG, "[fallback] App switched to background: " + state->last_foreground);
            dispatcher.notify_background(state->last_foreground);
        }
        if (cur != state->last_foreground) {
            LOG_I(TAG, "[fallback] App switched to foreground: " + cur);
            dispatcher.notify_foreground(cur);
            state->last_foreground = cur;
        }
        // 注：前台未变时不再重复调用 notify_foreground——它已经在首次
        // 切换时被加入 RunningCache 了，RunningCache 语义是"已知存活"
        // 而非"当前在前台"，不需要每轮都重新上报。

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

    // 关键：ring buffer 拉取线程必须先启动，再启动 shell 轮询的健康度
    // 判定循环。顺序反过来的话，shell 轮询第一次执行时 eBPF 事件循环
    // 还没开始拉取任何事件，last_ebpf_event_age_ms() 必然是"从未收到过"，
    // 会被误判为不健康，产生一次没有意义的"降级模式"日志。
    if (bpf_ok) bpf_loader.start_loop();

    // 启动前台检测调度（内部会根据 eBPF 健康状态决定是否真正接管驱动）
    schedule_top_app_refresh(bpf_loader, dispatcher, bpf_ok);

    init_lists(dispatcher);
    FreezeEngine::instance().start_freezer_guard();

    HttpServer http;
    if (!http.start()) return 1;

    LOG_I(TAG, "Running. PID=" + std::to_string(getpid()));

    while (g_running) { pause(); }

    LOG_I(TAG, "Shutting down");
    if (bpf_ok) bpf_loader.stop();
    http.stop();
    TimerManager::instance().stop();
    remove_pid_file();
    return 0;
}