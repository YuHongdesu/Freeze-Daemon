#pragma once
#include <string>
#include <sstream>
#include <queue>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cctype>
#include "core/config_store.h"
#include "core/app_list.h"
#include "core/app_state.h"
#include "core/app_label_cache.h"
#include "core/freeze_engine.h"
#include "util/logger.h"
#include "util/file_util.h"
#include "util/constants.h"
#include "util/reboot_flag.h"

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
        addr.sin_addr.s_addr = INADDR_ANY;   // 0.0.0.0，允许 KernelSU 等访问
        addr.sin_port        = htons(PORT);
        if (::bind(server_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_E(TAG, "bind() failed on port " + std::to_string(PORT)); return false;
        }
        ::listen(server_fd_, 8);
        running_ = true;
        accept_thread_ = std::thread(&HttpServer::accept_loop, this);
        LOG_I(TAG, "HTTP API + UI listening on http://0.0.0.0:" + std::to_string(PORT));
        return true;
    }

    void stop() {
        running_ = false;
        ::shutdown(server_fd_, SHUT_RDWR);
        if (accept_thread_.joinable()) accept_thread_.join();
        ::close(server_fd_);
        server_fd_ = -1;
    }

private:
    struct Request {
        std::string method;
        std::string path;
        std::string body;
    };

    Request parse_request(const std::string& raw) {
        Request req;
        std::istringstream iss(raw);
        iss >> req.method >> req.path;
        auto qpos = req.path.find('?');
        if (qpos != std::string::npos) req.path.resize(qpos);
        auto pos = raw.find("\r\n\r\n");
        if (pos != std::string::npos) req.body = raw.substr(pos + 4);
        return req;
    }

    std::string handle(const Request& req) {
        // 静态文件
        if (req.path == "/" || req.path == "/index.html") return serve_static_file("index.html");

        // API 路由
        if (req.path == "/api/status")             return handle_status();
        if (req.path == "/api/live")               return handle_live();
        if (req.path == "/api/apps/user")          return handle_apps_user();
        if (req.path == "/api/apps/system")        return handle_apps_system();
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

    // ── 状态接口 ──
    std::string handle_status() {
        std::ostringstream oss;
        oss << R"({"running":true,"needs_reboot":)"
            << (RebootFlag::has_pending() ? "true" : "false") << "}";
        return json_response(200, oss.str());
    }

    std::string handle_live() {
        auto frozen  = AppStateStore::instance().get_frozen_packages();
        auto running = RunningCache::instance().get_all();
        size_t user_frozen = 0;
        for (const auto& pkg : frozen)
            if (!AppList::instance().is_sys_restricted(pkg)) user_frozen++;
        size_t sys_limited = AppList::instance().get_sys_blacklist().size();

        std::ostringstream oss;
        oss << R"({"total_frozen":)"  << frozen.size()
            << R"(,"total_running":)" << running.size()
            << R"(,"user_frozen":)"   << user_frozen
            << R"(,"sys_limited":)"   << sys_limited
            << R"(,"apps":[)";
        for (size_t i = 0; i < frozen.size(); ++i) {
            if (i) oss << ",";
            oss << R"({"pkg":")" << frozen[i] << R"(","name":")" << AppLabelCache::instance().get_label(frozen[i])
                << R"(","procs":1,"mem":"—"})";
        }
        oss << "]}";
        return json_response(200, oss.str());
    }

    // ── 应用列表 ──
    std::string handle_apps_user() {
        auto apps = query_packages("pm list packages -3 -U 2>/dev/null");
        for (auto& a : apps) a.name = AppLabelCache::instance().get_label(a.pkg);
        return json_response(200, apps_json(apps));
    }
    std::string handle_apps_system() {
        auto apps = query_packages("pm list packages -s -U 2>/dev/null");
        for (auto& a : apps) a.name = AppLabelCache::instance().get_label(a.pkg);
        return json_response(200, apps_json(apps));
    }

    // ── 配置（改进的解析和 no-cache）──
    std::string handle_config_get() {
        Config cfg = ConfigStore::instance().get();
        std::ostringstream oss;
        auto b = [](bool v){ return v ? "true" : "false"; };
        oss << "{"
            << R"("bg_delay":)"            << cfg.bg_freeze_delay_ms / 1000
            << R"(,"screen_off_delay":)"   << cfg.screen_off_delay_ms / 1000
            << R"(,"compaction":)"         << b(cfg.compaction_on)
            << R"(,"wifi_scan":)"          << b(!cfg.wifi_scan_off)
            << R"(,"deep_sleep":)"         << b(cfg.deep_sleep_on)
            << R"(,"deep_sleep_delay":)"   << cfg.deep_sleep_delay_ms / 1000
            << R"(,"user_appop_restrict":)"<< b(cfg.user_appop_restrict)
            << "}";
        return json_response_no_cache(oss.str());
    }

    std::string handle_config_set(const std::string& body) {
        Config cfg = ConfigStore::instance().get();
        cfg.bg_freeze_delay_ms   = parse_int (body, "bg_delay",           cfg.bg_freeze_delay_ms / 1000) * 1000;
        cfg.screen_off_delay_ms  = parse_int (body, "screen_off_delay",   cfg.screen_off_delay_ms / 1000) * 1000;
        cfg.compaction_on        = parse_bool(body, "compaction",          cfg.compaction_on);
        cfg.wifi_scan_off        = !parse_bool(body, "wifi_scan",          !cfg.wifi_scan_off);
        cfg.deep_sleep_on        = parse_bool(body, "deep_sleep",          cfg.deep_sleep_on);
        cfg.deep_sleep_delay_ms  = parse_int (body, "deep_sleep_delay",   cfg.deep_sleep_delay_ms / 1000) * 1000;
        cfg.user_appop_restrict  = parse_bool(body, "user_appop_restrict", cfg.user_appop_restrict);

        bool ok = ConfigStore::instance().save(cfg);
        return json_response(ok ? 200 : 500,
                             ok ? R"({"ok":true})" : R"({"error":"save failed"})");
    }

    // ── 黑白名单 ──
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
            ok = add ? AppList::instance().add_user_exempt(pkg)
                     : AppList::instance().remove_user_exempt(pkg);
        } else {
            ok = add ? AppList::instance().add_sys_restricted(pkg)
                     : AppList::instance().remove_sys_restricted(pkg);
            if (ok) RebootFlag::mark("system_blacklist");
        }
        return json_response(ok ? 200 : 500,
                             ok ? R"({"ok":true})" : R"({"error":"failed"})");
    }

    // ── 静态文件（已加 CORS 头） ──
    static constexpr const char* WEBROOT = "/data/adb/modules/freeze-daemon/webroot/";

    std::string serve_static_file(const std::string& filename) {
        for (char c : filename) {
            if (!isalnum(c) && c != '.' && c != '_' && c != '-')
                return json_response(403, R"({"error":"forbidden"})");
        }
        std::string full = std::string(WEBROOT) + filename;
        auto content = FileUtil::read_str(full);
        if (!content) return json_response(404, R"({"error":"not found"})");

        std::string ext = full.substr(full.rfind('.'));
        std::string mime = "text/html";
        if (ext == ".css") mime = "text/css";
        else if (ext == ".js") mime = "application/javascript";
        else if (ext == ".svg") mime = "image/svg+xml";

        std::ostringstream oss;
        oss << "HTTP/1.1 200 OK\r\n"
            << "Content-Type: " << mime << "\r\n"
            << "Access-Control-Allow-Origin: *\r\n"
            << "Cache-Control: max-age=3600\r\n"
            << "Content-Length: " << content->size() << "\r\n"
            << "\r\n" << *content;
        return oss.str();
    }

    // ── 工具函数 ──
    struct AppInfo { std::string pkg, name; };
    std::vector<AppInfo> query_packages(const std::string& cmd) {
        std::vector<AppInfo> apps;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return apps;
        char buf[512];
        while (fgets(buf, sizeof(buf), pipe)) {
            std::string line(buf);
            auto p = line.find("package:");
            auto u = line.find("uid:");
            if (p == std::string::npos || u == std::string::npos) continue;
            std::string pkg = line.substr(p + 8, u - (p + 8) - 1);
            if (!pkg.empty()) apps.push_back({pkg, pkg});
        }
        pclose(pipe);
        return apps;
    }

    std::string apps_json(const std::vector<AppInfo>& apps) {
        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < apps.size(); ++i) {
            if (i) oss << ",";
            oss << R"({"pkg":")" << apps[i].pkg << R"(","name":")" << apps[i].name << R"("})";
        }
        oss << "]";
        return oss.str();
    }

    // ── 改进的 JSON 解析（容忍空格，直接提取数字/布尔/字符串）──
    int parse_int(const std::string& json, const std::string& key, int def) {
        std::string search = "\"" + key + "\":";
        auto pos = json.find(search);
        if (pos == std::string::npos) return def;
        pos += search.size();
        // 跳过空白
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) pos++;
        // 提取数字（支持负数）
        std::string val_str;
        if (pos < json.size() && (json[pos] == '-' || isdigit(json[pos]))) {
            while (pos < json.size() && (isdigit(json[pos]) || json[pos] == '-')) {
                val_str += json[pos++];
            }
        }
        if (val_str.empty()) return def;
        try { return std::stoi(val_str); } catch (...) { return def; }
    }

    bool parse_bool(const std::string& json, const std::string& key, bool def) {
        std::string search = "\"" + key + "\":";
        auto pos = json.find(search);
        if (pos == std::string::npos) return def;
        pos += search.size();
        // 跳过空白
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) pos++;
        if (pos + 4 <= json.size() && json.substr(pos, 4) == "true") return true;
        if (pos + 5 <= json.size() && json.substr(pos, 5) == "false") return false;
        return def;
    }

    std::string parse_str(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        auto end = json.find("\"", pos);
        return (end == std::string::npos) ? "" : json.substr(pos, end - pos);
    }

    std::string json_response(int code, const std::string& body) {
        std::string status = (code == 200) ? "200 OK"
                           : (code == 400) ? "400 Bad Request"
                           : (code == 404) ? "404 Not Found"
                           : (code == 403) ? "403 Forbidden" : "500 Internal Server Error";
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Access-Control-Allow-Origin: *\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "\r\n" << body;
        return oss.str();
    }

    std::string json_response_no_cache(const std::string& body) {
        std::ostringstream oss;
        oss << "HTTP/1.1 200 OK\r\n"
            << "Content-Type: application/json\r\n"
            << "Access-Control-Allow-Origin: *\r\n"
            << "Cache-Control: no-cache, no-store, must-revalidate\r\n"
            << "Pragma: no-cache\r\n"
            << "Expires: 0\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "\r\n" << body;
        return oss.str();
    }

    // ── 线程池 ──
    // 关键修复：之前这里被设成了 1，导致所有请求排队串行处理。
    // /api/apps/user、/api/apps/system 内部会 popen("pm list packages ...")，
    // 这条 shell 命令在应用较多的设备上常需要几百毫秒甚至更久；
    // 单线程时，这类慢请求会独占唯一的 worker，导致同一时间段内
    // 排在后面的 /api/live（3 秒轮询一次）、/api/status（前端设了
    // 2 秒超时）等请求被阻塞甚至超时，表现为"网页显示无法连接 Daemon"、
    // "实时状态转圈不出数据"。恢复成多线程可以让慢请求和高频轻量
    // 请求互不阻塞。
    static constexpr int WORKER_COUNT = 4;

    void accept_loop() {
        for (int i = 0; i < WORKER_COUNT; ++i)
            workers_.emplace_back(&HttpServer::worker_loop, this);
        while (running_) {
            int client = ::accept(server_fd_, nullptr, nullptr);
            if (client < 0) continue;
            push_client(client);
        }
        {
            std::lock_guard<std::mutex> lk(queue_mutex_);
            shutting_down_ = true;
        }
        queue_cv_.notify_all();
        for (auto& w : workers_) if (w.joinable()) w.join();
    }

    void push_client(int fd) {
        { std::lock_guard<std::mutex> lk(queue_mutex_); client_queue_.push(fd); }
        queue_cv_.notify_one();
    }

    void worker_loop() {
        while (true) {
            int fd = -1;
            {
                std::unique_lock<std::mutex> lk(queue_mutex_);
                queue_cv_.wait(lk, [this]{ return shutting_down_ || !client_queue_.empty(); });
                if (shutting_down_ && client_queue_.empty()) return;
                fd = client_queue_.front(); client_queue_.pop();
            }
            try { handle_client(fd); }
            catch (const std::exception& e) { LOG_E(TAG, std::string("Worker: ") + e.what()); }
            catch (...) { LOG_E(TAG, "Worker unknown exception"); }
        }
    }

    // 关键修复：TCP 是流式协议，一次 recv() 不保证读到完整的 HTTP 请求——
    // header 和 body 完全可能被分成多个 TCP 段，尤其是请求体稍大或者
    // fetch() 的具体实现把它们分开发送时。旧实现只做一次 recv 就直接
    // 交给 parse_request，读到半截请求时 body 会被截断甚至整体丢失，
    // 表现为"接口有时候莫名其妙不生效"。这里改成先读满 header，解析
    // Content-Length，再循环读满声明的 body 长度，同时设读超时防止
    // 恶意/异常连接让 worker 线程永久卡住。
    static constexpr size_t MAX_REQUEST_BYTES = 1 * 1024 * 1024;  // 1MB 上限，防止异常超大 body 打爆内存
    static constexpr int    RECV_TIMEOUT_SEC  = 5;

    void handle_client(int fd) {
        timeval tv{RECV_TIMEOUT_SEC, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        std::string raw;
        char buf[4096];

        // 第一阶段：读到 \r\n\r\n（header 结束）为止
        size_t header_end = std::string::npos;
        while (header_end == std::string::npos) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) { ::close(fd); return; }  // 对端关闭 / 超时 / 出错
            raw.append(buf, n);
            if (raw.size() > MAX_REQUEST_BYTES) { ::close(fd); return; }
            header_end = raw.find("\r\n\r\n");
        }

        // 第二阶段：从 header 里取 Content-Length，循环读满 body
        size_t content_length = parse_content_length(raw);
        size_t body_have = raw.size() - (header_end + 4);
        while (content_length > 0 && body_have < content_length) {
            if (raw.size() > MAX_REQUEST_BYTES) { ::close(fd); return; }
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;  // 对端提前关闭/超时：按已收到的部分处理，不无限等
            raw.append(buf, n);
            body_have += n;
        }

        Request req = parse_request(raw);
        std::string resp = handle(req);
        send_all(fd, resp);
        ::close(fd);
    }

    // 大小写不敏感地从 header 里找 Content-Length（HTTP header 名不区分大小写，
    // 不同客户端实现大小写风格不一定一致，只匹配精确的 "Content-Length:" 不够稳）
    size_t parse_content_length(const std::string& raw) {
        size_t header_end = raw.find("\r\n\r\n");
        std::string headers = (header_end != std::string::npos) ? raw.substr(0, header_end) : raw;
        std::string lower = headers;
        for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        auto pos = lower.find("content-length:");
        if (pos == std::string::npos) return 0;
        pos += 15;
        while (pos < headers.size() && headers[pos] == ' ') pos++;
        size_t val = 0;
        try { val = std::stoul(headers.substr(pos)); } catch (...) { return 0; }
        return val;
    }

    // send() 同样不保证一次写完全部数据，短写时需要循环补发
    void send_all(int fd, const std::string& data) {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
            if (n <= 0) return;  // 对端已断开，放弃剩余发送
            sent += static_cast<size_t>(n);
        }
    }

    int server_fd_{-1};
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::vector<std::thread> workers_;
    std::queue<int> client_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    bool shutting_down_{false};
};