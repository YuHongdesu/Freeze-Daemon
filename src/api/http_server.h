#pragma once
#include <string>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <queue>
#include <condition_variable>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include "core/config_store.h"
#include "core/app_list.h"
#include "core/app_state.h"
#include "core/freeze_engine.h"   // RunningCache
#include "util/logger.h"
#include "util/reboot_flag.h"

// 接口层：HTTP API，只做请求解析和响应序列化，不含业务逻辑
class HttpServer {
public:
    static constexpr const char* TAG  = "HttpServer";
    static constexpr int         PORT = 9572;

    bool start() {
        server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) { LOG_E(TAG, "socket() failed"); return false; }

        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(PORT);

        if (::bind(server_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_E(TAG, "bind() failed on port " + std::to_string(PORT)); return false;
        }
        ::listen(server_fd_, 8);
        running_ = true;
        accept_thread_ = std::thread(&HttpServer::accept_loop, this);
        LOG_I(TAG, "HTTP API listening on :" + std::to_string(PORT));
        return true;
    }

    void stop() {
        running_ = false;
        ::shutdown(server_fd_, SHUT_RDWR);  // 让 accept() 立即返回错误
        ::close(server_fd_);
        server_fd_ = -1;
        if (accept_thread_.joinable()) accept_thread_.join();
    }

private:
    // ── 请求解析 ─────────────────────────────────────────────

    struct Request {
        std::string method;
        std::string path;
        std::string body;
    };

    Request parse_request(const std::string& raw) {
        Request req;
        std::istringstream iss(raw);
        iss >> req.method >> req.path;
        // 查找 body（\r\n\r\n 之后）
        auto pos = raw.find("\r\n\r\n");
        if (pos != std::string::npos) req.body = raw.substr(pos + 4);
        return req;
    }

    // ── 路由分发 ─────────────────────────────────────────────

    std::string handle(const Request& req) {
        if (req.path == "/api/status")             return handle_status();
        if (req.path == "/api/live")               return handle_live();
        if (req.path == "/api/config" && req.method == "GET")  return handle_config_get();
        if (req.path == "/api/config" && req.method == "POST") return handle_config_set(req.body);
        if (req.path == "/api/whitelist")           return handle_list_get(ListType::WHITELIST);
        if (req.path == "/api/blacklist")           return handle_list_get(ListType::BLACKLIST);
        if (req.path == "/api/whitelist/add")       return handle_list_modify(req.body, ListType::WHITELIST, true);
        if (req.path == "/api/whitelist/remove")    return handle_list_modify(req.body, ListType::WHITELIST, false);
        if (req.path == "/api/blacklist/add")       return handle_list_modify(req.body, ListType::BLACKLIST, true);
        if (req.path == "/api/blacklist/remove")    return handle_list_modify(req.body, ListType::BLACKLIST, false);
        return json_response(404, R"({"error":"not found"})");
    }

    // ── 各接口实现 ────────────────────────────────────────────

    std::string handle_status() {
        std::ostringstream oss;
        oss << R"({"running":true,"needs_reboot":)"
            << (RebootFlag::has_pending() ? "true" : "false")
            << "}";
        return json_response(200, oss.str());
    }

    std::string handle_live() {
        auto frozen  = AppStateStore::instance().get_frozen_packages();
        auto running = RunningCache::instance().get_all();

        // 区分用户app冻结 vs 系统app（黑名单限制不体现在冻结状态里）
        size_t user_frozen = 0;
        for (const auto& pkg : frozen) {
            if (!AppList::instance().is_sys_restricted(pkg)) user_frozen++;
        }
        size_t sys_limited = AppList::instance().get_sys_blacklist().size();

        std::ostringstream oss;
        oss << R"({"total_frozen":)"  << frozen.size()
            << R"(,"total_running":)" << running.size()
            << R"(,"user_frozen":)"   << user_frozen
            << R"(,"sys_limited":)"   << sys_limited
            << R"(,"apps":[)";
        for (size_t i = 0; i < frozen.size(); ++i) {
            if (i) oss << ",";
            // pkg name 作为 name 展示（Daemon 无 PackageManager，显示包名）
            const auto& pkg = frozen[i];
            oss << R"({"pkg":")" << pkg << R"(","name":")" << pkg
                << R"(","procs":1,"mem":"—"})";
        }
        oss << "]}";
        return json_response(200, oss.str());
    }

    std::string handle_config_get() {
        Config cfg = ConfigStore::instance().get();
        std::ostringstream oss;
        auto b = [](bool v){ return v ? "true" : "false"; };
        oss << "{"
            << R"("bg_delay":)"            << cfg.bg_freeze_delay_ms / 1000
            << R"(,"screen_off_delay":)"   << cfg.screen_off_delay_ms / 1000
            << R"(,"compaction":)"         << b(cfg.compaction_on)
            << R"(,"wifi_scan":)"          << b(cfg.wifi_scan_off)
            << R"(,"deep_sleep":)"         << b(cfg.deep_sleep_on)
            << R"(,"deep_sleep_delay":)"   << cfg.deep_sleep_delay_ms / 1000
            << R"(,"user_appop_restrict":)"<< b(cfg.user_appop_restrict)
            << "}";
        return json_response(200, oss.str());
    }

    std::string handle_config_set(const std::string& body) {
        Config cfg = ConfigStore::instance().get();
        cfg.bg_freeze_delay_ms   = parse_int (body, "bg_delay",           cfg.bg_freeze_delay_ms / 1000) * 1000;
        cfg.screen_off_delay_ms  = parse_int (body, "screen_off_delay",   cfg.screen_off_delay_ms / 1000) * 1000;
        cfg.compaction_on        = parse_bool(body, "compaction",          cfg.compaction_on);
        cfg.wifi_scan_off        = parse_bool(body, "wifi_scan",           cfg.wifi_scan_off);
        cfg.deep_sleep_on        = parse_bool(body, "deep_sleep",          cfg.deep_sleep_on);
        cfg.deep_sleep_delay_ms  = parse_int (body, "deep_sleep_delay",   cfg.deep_sleep_delay_ms / 1000) * 1000;
        cfg.user_appop_restrict  = parse_bool(body, "user_appop_restrict", cfg.user_appop_restrict);

        bool ok = ConfigStore::instance().save(cfg);
        return json_response(ok ? 200 : 500,
                             ok ? R"({"ok":true})" : R"({"error":"save failed"})");
    }

    enum class ListType { WHITELIST, BLACKLIST };

    std::string handle_list_get(ListType type) {
        auto list = (type == ListType::WHITELIST)
                  ? AppList::instance().get_user_whitelist()
                  : AppList::instance().get_sys_blacklist();
        std::ostringstream oss;
        oss << R"({"list":[)";
        bool first = true;
        for (const auto& pkg : list) {
            if (!first) oss << ",";
            oss << "\"" << pkg << "\"";
            first = false;
        }
        oss << "]}";
        return json_response(200, oss.str());
    }

    std::string handle_list_modify(const std::string& body, ListType type, bool add) {
        std::string pkg = parse_str(body, "pkg");
        if (pkg.empty()) return json_response(400, R"({"error":"pkg required"})");

        bool ok;
        if (type == ListType::WHITELIST) {
            // 白名单（用户app豁免冻结）实时生效：FreezeEngine 每次决策都
            // 现查 AppList::is_user_exempt()，不需要重启
            ok = add ? AppList::instance().add_user_exempt(pkg)
                     : AppList::instance().remove_user_exempt(pkg);
        } else {
            // 黑名单（系统app限制）不会立即生效：实际的 AppOp 剥夺 +
            // 踢出 Doze 白名单只在 service.sh 的 apply_system_blacklist()
            // 里执行一次（开机时），Daemon 运行期间不会重新调用这段逻辑，
            // 借鉴 Frosty 的 *_needs_reboot 标记机制提示用户
            ok = add ? AppList::instance().add_sys_restricted(pkg)
                     : AppList::instance().remove_sys_restricted(pkg);
            if (ok) RebootFlag::mark("system_blacklist");
        }

        return json_response(ok ? 200 : 500,
                             ok ? R"({"ok":true})" : R"({"error":"failed"})");
    }

    // ── 极简 JSON 解析（带异常保护）────────────────────────────

    int parse_int(const std::string& json, const std::string& key, int def) {
        std::string search = "\"" + key + "\":";
        auto pos = json.find(search);
        if (pos == std::string::npos) return def;
        pos += search.size();
        try { return std::stoi(json.substr(pos)); }
        catch (...) { return def; }
    }

    bool parse_bool(const std::string& json, const std::string& key, bool def) {
        std::string search = "\"" + key + "\":";
        auto pos = json.find(search);
        if (pos == std::string::npos) return def;
        pos += search.size();
        if (pos + 4 > json.size()) return def;
        return json.substr(pos, 4) == "true";
    }

    std::string parse_str(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        auto end = json.find("\"", pos);
        return (end == std::string::npos) ? "" : json.substr(pos, end - pos);
    }

    // ── HTTP 响应构造 ─────────────────────────────────────────

    std::string json_response(int code, const std::string& body) {
        std::string status = (code == 200) ? "200 OK"
                           : (code == 400) ? "400 Bad Request"
                           : (code == 404) ? "404 Not Found"
                                           : "500 Internal Server Error";
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Access-Control-Allow-Origin: *\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "\r\n" << body;
        return oss.str();
    }

    // ── Socket accept 循环 + 固定线程池 ──────────────────────
    // 性能优化：原实现每个连接 detach 一个新线程，高频轮询场景下
    // （Web UI 每 3 秒请求一次 /api/live）频繁创建/销毁线程有不小的
    // 系统调用开销。改为固定数量的 worker 线程从队列里取连接处理，
    // 避免每次请求都付出线程创建成本。

    static constexpr int WORKER_COUNT = 4;

    void accept_loop() {
        for (int i = 0; i < WORKER_COUNT; ++i) {
            workers_.emplace_back(&HttpServer::worker_loop, this);
        }
        while (running_) {
            int client = ::accept(server_fd_, nullptr, nullptr);
            if (client < 0) continue;
            push_client(client);
        }
        // 通知所有 worker 退出
        {
            std::lock_guard<std::mutex> lk(queue_mutex_);
            shutting_down_ = true;
        }
        queue_cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
    }

    void push_client(int fd) {
        {
            std::lock_guard<std::mutex> lk(queue_mutex_);
            client_queue_.push(fd);
        }
        queue_cv_.notify_one();
    }

    void worker_loop() {
        while (true) {
            int fd = -1;
            {
                std::unique_lock<std::mutex> lk(queue_mutex_);
                queue_cv_.wait(lk, [this]{ return shutting_down_ || !client_queue_.empty(); });
                if (shutting_down_ && client_queue_.empty()) return;
                fd = client_queue_.front();
                client_queue_.pop();
            }
            handle_client(fd);
        }
    }

    void handle_client(int fd) {
        char buf[4096] = {};
        ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { ::close(fd); return; }

        Request req = parse_request(std::string(buf, n));
        std::string resp = handle(req);
        ::send(fd, resp.c_str(), resp.size(), 0);
        ::close(fd);
    }

    int               server_fd_{-1};
    std::atomic<bool> running_{false};
    std::thread       accept_thread_;

    // 固定 worker 线程池，避免每个请求都创建/销毁新线程
    std::vector<std::thread> workers_;
    std::queue<int>          client_queue_;
    std::mutex                queue_mutex_;
    std::condition_variable   queue_cv_;
    bool                       shutting_down_{false};
};
