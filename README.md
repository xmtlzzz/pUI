# pUI

**pUI · 抓包报文时序分析** — 跨平台(Win / macOS / Linux)桌面抓包分析工具。基于 Tauri 2 + React,以 Wireshark 的 `tshark` 为解析引擎,打开 pcap/pcapng 后按协议/地址/端口筛选,自动聚合双向会话,并把报文交互渲染成带时间戳的时序图。

**pUI · Packet Flow Sequence Analyzer** — a cross-platform (Win / macOS / Linux) desktop packet-analyzer built on Tauri 2 + React with Wireshark's `tshark` as its parsing engine. Open a pcap/pcapng, filter by protocol / address / port, aggregate bidirectional conversations automatically, and render packet interactions as a timestamped sequence diagram.

---

## ✨ 特性 / Features

- **打开抓包**:支持 pcap / pcapng,可拖拽文件到窗口,内置 4 个示例抓包
  **Open captures**: pcap / pcapng, drag-and-drop onto the window, plus 4 built-in example captures
- **会话级筛选**:协议、源/目的 IP、源/目的端口,支持取反与「仅看异常会话」
  **Conversation-level filtering**: protocol, source/destination IP, source/destination port, with negation and an "issues only" mode
- **双向会话聚合**:自动归一化五元组、判定客户端/服务端,兼容 IPv4 / IPv6 / MAC
  **Bidirectional aggregation**: auto-normalizes 5-tuples and detects client/server (IPv4 / IPv6 / MAC aware)
- **时序图双风格**:A(斜线)/ B(横向行),含时间戳、报文长度、方向颜色、全协议配色
  **Two sequence styles**: A (slanted) / B (horizontal rows), with timestamps, packet length, direction colors and per-protocol colors
- **报文详情**:键值信息 + hex dump
  **Packet detail**: key-value info + hex dump
- **PNG 导出**:导出当前会话时序图(自动剥离缩放)
  **PNG export**: exports the current sequence diagram (zoom stripped automatically)
- **丢包/异常检测**:重传、乱序、重复 ACK、丢段、慢响应、SYN 无应答、未关闭、RST、请求无响应
  **Loss / anomaly detection**: retransmission, out-of-order, duplicate ACK, lost segment, slow response, SYN-unanswered, no-close, RST, unanswered request
- **一体化 UI**:自绘标题栏、可拖拽并持久化面板尺寸
  **Integrated UI**: custom title bar, draggable & persisted panel sizes

## 🧱 技术栈 / Tech Stack

| 层 Layer | 技术 Tech |
|---|---|
| 桌面壳 Desktop shell | [Tauri 2](https://tauri.app/) (Rust) |
| 前端 Frontend | React 19 · TypeScript · Vite 7 · Zustand 5 |
| 解析引擎 Parsing engine | tshark (Wireshark CLI) |
| 时序图 Sequence diagram | 自定义 SVG 渲染 custom SVG rendering |
| 测试 Tests | Vitest 4 · Rust `cargo test` |

## 📦 环境依赖 / Prerequisites

- **tshark**(Wireshark 命令行解析器)—— 应用按「用户设置路径 → 随包资源 → PATH → 常见安装目录」顺序查找;需安装 Wireshark,或在设置中指定 tshark 路径。
  **tshark** (Wireshark CLI) — resolved in order: user-set path → bundled resource → `PATH` → common install locations. Install Wireshark, or point the app to `tshark` explicitly.
- **Rust**(cargo)与 **Node.js**(≥ 18),以及平台的 WebView2。
  **Rust** (cargo) and **Node.js** (≥ 18), plus the platform's WebView2.

## 🚀 构建与运行 / Build & Run

```bash
npm install

npm run tauri dev      # 开发模式(热更新) / development (HMR)
npm run tauri build    # 打包发布 / production bundle

npm test               # 前端测试 / frontend tests
cargo test --manifest-path src-tauri/Cargo.toml   # Rust 测试 / Rust tests
```

> 打包版为无控制台 GUI;子进程已加 `CREATE_NO_WINDOW`,不会闪现 cmd 窗口。
> The packaged app is a console-less GUI; child processes use `CREATE_NO_WINDOW`, so no console windows flash.

## 📖 使用说明 / Usage

1. **打开**:工具栏「打开文件」或拖拽 pcap/pcapng 到窗口;也可直接选择内置示例。
   **Open**: toolbar button, or drag a pcap/pcapng onto the window; built-in examples are one click away.
2. **筛选**:左侧面板按协议/源目 IP/端口筛选,勾选「取反」「仅看异常会话」。
   **Filter**: left panel filters by protocol / IP / port, with negation and "issues only".
3. **查看**:中间列表选中会话 → 右侧渲染时序图;点击任意报文查看详情与 hex。
   **Inspect**: pick a conversation in the middle list → sequence diagram renders on the right; click a packet for details + hex.
4. **导出**:右上「导出 PNG」保存当前时序图。
   **Export**: top-right "Export PNG" saves the current diagram.

## 🎯 内置示例 / Built-in Examples

| 示例 Example | 内容 Content |
|---|---|
| `http` | 完整 HTTP 请求/响应(含 FIN 关闭) full request/response with teardown |
| `dns` | DNS 查询/响应 query/response |
| `mixed` | ARP + DNS + HTTP 混合 mixed protocols |
| `lossy` | 丢包示例:重传 + 请求无应答 loss example: retransmission + unanswered |

## 🗂️ 项目结构 / Project Structure

```
src/             前端 / frontend (React + Zustand)
  parse/          tshark JSON → Packet 模型 / tshark JSON → Packet model
  aggregate/      会话聚合 + 丢包检测 / conversation aggregation + loss detection
  filter/         筛选逻辑 / filtering
  render/         时序图布局与渲染 / sequence layout & rendering
  app/            布局 · 工具条 · 筛选 · 会话列表 / layout, toolbar, filters, list
  detail/         报文详情 + hex / packet detail + hex
  export/         PNG 导出 / PNG export
  bridge/         Tauri IPC + 浏览器回退 / Tauri IPC + browser fallback
src-tauri/       Rust 后端(命令层 + tshark 进程管理)/ Rust backend
public/fixtures  内置示例抓包 / built-in example captures
docs/            需求 · 架构 · 决策 · 实现计划 / PRD · architecture · decisions · plan
scripts/         示例抓包与图标生成 / fixture & icon generators
```

## 📚 文档 / Docs

详见 [docs/README.md](docs/README.md)(产品需求、技术选型与架构、关键决策、实现计划)。
See [docs/README.md](docs/README.md) for the PRD, architecture, decisions and implementation plan.

---

*Built for packet-level troubleshooting & teaching. Bugs / ideas welcome.*
