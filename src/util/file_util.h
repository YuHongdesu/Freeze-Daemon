#pragma once
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <sstream>
#include <optional>
#include "logger.h"

namespace FileUtil {

constexpr const char* TAG = "FileUtil";

inline bool write_str(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f.is_open()) {
        LOG_E(TAG, "Cannot open for write: " + path);
        return false;
    }
    f << content;
    return f.good();
}

inline std::optional<std::string> read_str(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return std::nullopt;
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
}

// 读取文本文件，每行一个条目，忽略空行和 # 注释
inline std::set<std::string> read_lines_as_set(const std::string& path) {
    std::set<std::string> result;
    std::ifstream f(path);
    if (!f.is_open()) return result;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // 去除尾部空白
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        if (!line.empty()) result.insert(line);
    }
    return result;
}

inline bool write_lines(const std::string& path, const std::set<std::string>& lines) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    for (const auto& line : lines) f << line << "\n";
    return f.good();
}

inline bool file_exists(const std::string& path) {
    return std::ifstream(path).is_open();
}

} // namespace FileUtil
