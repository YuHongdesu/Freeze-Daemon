# Freeze Daemon

[![GitHub release](https://img.shields.io/github/v/release/yourusername/freeze-daemon)](https://github.com/yourusername/freeze-daemon/releases)
[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

**Freeze Daemon** 是一款基于 **KernelSU** + **eBPF** 的 Android 应用冻结守护进程。

它通过事件驱动的方式实现精准、轻量级的应用冻结，显著降低后台功耗，同时避免与系统原生 Freezer 冲突。

## ✨ 主要特性

- **eBPF 事件驱动**：实时监控前后台切换、屏幕亮灭、进程生命周期
- **独立 cgroup 子树**：与系统 uid_N cgroup 完全隔离，避免冲突
- **智能延迟冻结**：后台切换延迟 + 息屏批量冻结
- **系统 Freezer 防御**：自动检测并强制关闭系统 Freezer
- **AppOps 精细控制**：对非白名单应用剥夺后台权限
- **Web UI 管理**：KernelSU 管理器内直接通过浏览器配置
- **深度休眠支持**：可选开启 Deep Doze + Wi-Fi/BT 扫描关闭
- **极致优化**：LTO + 死代码剔除 + 符号剥离，低占用、低功耗

## 📥 安装方法

1. 下载最新 Release 中的 `freeze-daemon-*.zip`
2. 打开 **KernelSU** App → 模块 → 右上角 `+` → 选择 ZIP 文件安装
3. 重启手机
4. 在 KernelSU 管理器内打开 Web UI（默认端口 9572）进行配置

> **最低要求**：KernelSU 版本 ≥ 11143

## ⚙️ 配置说明

### 白名单 / 黑名单

- `user_whitelist.txt`：加入需要保持后台运行的应用（如微信、QQ）
- `system_blacklist.txt`：对系统应用进行限制（踢出 Doze + 剥夺 AppOps）

### 核心参数（可在 Web UI 修改）

- 后台冻结延迟（默认 5 秒）
- 息屏冻结延迟（默认 3 秒）
- 是否启用深度休眠
- 是否对用户 App 剥夺后台权限

## 🛠️ 编译指南

详见 [BUILD_GUIDE.md](BUILD_GUIDE.md)

推荐使用 GitHub Actions 一键编译（无需本地环境）。

## 📋 源码结构
util/          基础工具，零业务逻辑
  constants.h    所有常量和魔法数字集中管理
  logger.h       线程安全日志（异步批量 flush，无忙等阻塞）
  file_util.h    纯文件 I/O
  timer.h        timerfd + epoll，无忙等

core/          业务数据层 + 决策引擎
  config_store.h      配置读写（唯一操作 freeze.conf 的地方）
  app_list.h          白名单/黑名单读写（唯一操作 txt 文件的地方）
  app_state.h         每个 app 的冻结状态机（纯状态，无 I/O）
  deep_sleep_manager.h  深度休眠引擎（息屏延迟触发 Deep Doze，亮屏立即退出）
  freeze_engine.h     冻结决策引擎（唯一协调状态+cgroup+AppOp+timer+freezer防御的地方）

platform/      平台操作层
  cgroup_manager.h   cgroup v2 文件操作（含批量 pid 迁移）
  appop_manager.h    AppOp 权限剥夺/恢复（6 项权限）
  pid_cache.h        uid→pid 内存缓存，由 eBPF 事件维护，消除 /proc 遍历
  safety_checker.h   冻结前安全检查（音乐/导航/投屏）
  bpf_loader.h       eBPF 加载和 ring buffer 读取
  freeze_monitor.bpf.c  内核探针（感知前后台/屏幕/系统解冻）

api/           接口层
  event_dispatcher.h  eBPF 事件 → 业务层路由，uid→pkg 解析
  http_server.h       Web UI HTTP API

main.cpp       入口，只做初始化和连接，无业务逻辑
scripts/service.sh  静态层，开机一次性执行（关闭系统Freezer/系统黑名单/用户AppOp）

## 🔧 使用技术

- eBPF Ring Buffer + tracepoint 实现低开销事件监控
- PidCache 双向索引 + Fallback 机制确保前后台检测可靠
- 异步 Logger + 日志轮转
- epoll + timerfd 定时器
- 生产级编译优化（LTO + gc-sections + strip）

## ⚠️ 注意事项

- 本模块会**强制关闭系统 Freezer**，请勿与其他冻结类模块同时使用
- 深度休眠功能请根据实际 ROM 测试开启