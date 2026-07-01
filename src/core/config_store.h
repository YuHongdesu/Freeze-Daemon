#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <stdexcept>      // std::invalid_argument, std::out_of_range
#include "util/file_util.h"
#include "util/constants.h"
#include "util/logger.h"

struct Config {
    int  bg_freeze_delay_ms    = Default::BG_FREEZE_DELAY_MS;
    int  screen_off_delay_ms   = Default::SCREEN_OFF_DELAY_MS;
    int  bounce_limit          = Default::BOUNCE_LIMIT;
    int  bounce_backoff_ms     = Default::BOUNCE_BACKOFF_MS;
    bool compaction_on         = Default::COMPACTION_ON;
    bool wifi_scan_off         = Default::WIFI_SCAN_OFF;
    bool deep_sleep_on         = Default::DEEP_SLEEP_ON;
    int  deep_sleep_delay_ms   = Default::DEEP_SLEEP_DELAY_MS;
    bool user_appop_restrict   = Default::USER_APPOP_RESTRICT;
};

class ConfigStore {
public:
    static constexpr const char* TAG = "ConfigStore";

    static ConfigStore& instance() {
        static ConfigStore inst;
        return inst;
    }

    Config get() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return config_;
    }

    bool load() {
        auto content = FileUtil::read_str(Path::CONFIG_FILE);
        if (!content) {
            LOG_W(TAG, "Config file not found, using defaults");
            return false;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        config_ = parse(*content);
        LOG_I(TAG, "Config loaded");
        return true;
    }

    bool save(const Config& cfg) {
        std::string content = serialize(cfg);
        if (!FileUtil::write_str(Path::CONFIG_FILE, content)) return false;
        std::lock_guard<std::mutex> lk(mutex_);
        config_ = cfg;
        LOG_I(TAG, "Config saved");
        return true;
    }

    void reset_to_default() {
        save(Config{});
    }

private:
    ConfigStore() { load(); }

    // key=value 格式解析，带异常保护
    Config parse(const std::string& content) {
        Config cfg;
        std::istringstream iss(content);
        std::string line;
        int line_no = 0;
        while (std::getline(iss, line)) {
            line_no++;
            auto pos = line.find('=');
            if (pos == std::string::npos || line[0] == '#') continue;
            std::string key = trim(line.substr(0, pos));
            std::string val = trim(line.substr(pos + 1));
            if (key.empty()) continue;  // 忽略空键

            try {
                apply_kv(cfg, key, val);
            } catch (const std::exception& e) {
                LOG_W(TAG, "Config parse error at line " + std::to_string(line_no) +
                           ": " + e.what() + " (key=" + key + ", val=" + val + ")");
            } catch (...) {
                LOG_W(TAG, "Config parse unknown error at line " + std::to_string(line_no));
            }
        }
        return cfg;
    }

    void apply_kv(Config& cfg, const std::string& key, const std::string& val) {
        // 安全的数字转换：捕获非法值异常
        auto safe_stoi = [](const std::string& s) -> int {
            if (s.empty()) throw std::invalid_argument("empty value");
            return std::stoi(s);
        };

        if      (key == "bg_freeze_delay_ms")    cfg.bg_freeze_delay_ms   = safe_stoi(val);
        else if (key == "screen_off_delay_ms")   cfg.screen_off_delay_ms  = safe_stoi(val);
        else if (key == "bounce_limit")          cfg.bounce_limit         = safe_stoi(val);
        else if (key == "bounce_backoff_ms")     cfg.bounce_backoff_ms    = safe_stoi(val);
        else if (key == "compaction_on")         cfg.compaction_on        = (val == "1" || val == "true");
        else if (key == "wifi_scan_off")         cfg.wifi_scan_off        = (val == "1" || val == "true");
        else if (key == "deep_sleep_on")         cfg.deep_sleep_on        = (val == "1" || val == "true");
        else if (key == "deep_sleep_delay_ms")   cfg.deep_sleep_delay_ms  = safe_stoi(val);
        else if (key == "user_appop_restrict")   cfg.user_appop_restrict  = (val == "1" || val == "true");
        // 未知键忽略，不抛异常
    }

    std::string serialize(const Config& cfg) {
        std::ostringstream oss;
        auto b = [](bool v){ return v ? "true" : "false"; };
        oss << "bg_freeze_delay_ms="   << cfg.bg_freeze_delay_ms   << "\n"
            << "screen_off_delay_ms="  << cfg.screen_off_delay_ms  << "\n"
            << "bounce_limit="         << cfg.bounce_limit         << "\n"
            << "bounce_backoff_ms="    << cfg.bounce_backoff_ms    << "\n"
            << "compaction_on="        << b(cfg.compaction_on)     << "\n"
            << "wifi_scan_off="        << b(cfg.wifi_scan_off)     << "\n"
            << "deep_sleep_on="        << b(cfg.deep_sleep_on)     << "\n"
            << "deep_sleep_delay_ms="  << cfg.deep_sleep_delay_ms  << "\n"
            << "user_appop_restrict="  << b(cfg.user_appop_restrict) << "\n";
        return oss.str();
    }

    std::string trim(std::string s) {
        size_t l = s.find_first_not_of(" \t\r");
        size_t r = s.find_last_not_of(" \t\r");
        return (l == std::string::npos) ? "" : s.substr(l, r - l + 1);
    }

    mutable std::mutex mutex_;
    Config             config_;
};