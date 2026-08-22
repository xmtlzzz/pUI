# pUI

**pUI · 抓包报文时序分析** — 跨平台(Win / macOS / Linux)桌面抓包分析工具。基于 Tauri 2 + React,以 Wireshark 的 `tshark` 为解析引擎:打开 pcap/pcapng 后按协议/地址/端口/异常类型筛选,自动聚合双向会话,把报文交互渲染成带时间戳的时序图,并提供主机视角、分析摘要、时间窗下钻、报文搜索等排查能力。

**pUI · Packet Flow Sequence Analyzer** — a cross-platform desktop packet analyzer on Tauri 2 + React with Wireshark's `tshark` as the parsing engine: filter by protocol / address / port / issue type, aggregate bidirectional conversations, render packet interactions as a timestamped sequence diagram, plus host view, analysis summary, time-window drill-down and packet search.

---

## ✨ 特性 / Features

- **打开抓包**:pcap / pcapng,拖拽或对话框打开,内置 4 个示例;文件概览显示真实接口数、解析耗时与 tshark 版本
  **Open captures**: pcap / pcapng via drag-and-drop or dialog, 4 built-in examples; real interface count, parse time and tshark version in the overview
- **会话级筛选**:协议、源/目的 IP、源/目的端口,取反,仅看异常,并按异常类型细化(重传/乱序/重复ACK/丢段/慢响应/未关闭/被重置/请求无响应/连接未建立/单向),慢响应阈值可调
  **Conversation-level filtering**: protocol / IP / port with negation, issues-only, per issue-type refinement and a configurable slow-response threshold
- **双向会话聚合**:五元组归一化、自动判定客户端/服务端(IPv4 / IPv6 / MAC),中途接入/缺端口等畸形数据不致会话错分
  **Bidirectional aggregation**: 5-tuple normalization with client/server detection, robust to mid-stream captures and missing ports
- **丢包/异常检测**:重传、乱序、重复 ACK、丢段、慢响应、SYN 无应答、未正常关闭、RST、HTTP/DNS 请求无响应、单向会话;规则对照真实流量行为(中途抓包片段、重传 SYN、Keep-Alive 悬挂请求、204/304 无 body 响应等不误报)
  **Loss / anomaly detection**: retransmission, out-of-order, dup-ACK, lost segment, slow response, SYN-unanswered, no-close, RST, unanswered HTTP/DNS, one-way — false-positive aware for real-world traffic shapes
- **会话列表**:列头排序(客户端/服务端/协议/包/字节/时长/开始时间)、报文全文搜索(协议/地址/端口/URL/DNS/标志)并可定位高亮、超长列表窗口化渲染
  **Conversation list**: sortable columns, full-text packet search with locate-and-highlight, windowed rendering for huge captures
- **时序图**:A 斜线 / B 行式双风格,相对/绝对时间戳切换,长会话按空闲间隔自动分段导航,>2000 报文自动抽稀降级(首尾保底),hover 悬停、缩放、协议/方向配色,搜索/时间窗命中紫色高亮
  **Sequence diagram**: styles A/B, relative/absolute timestamps, idle-gap segment navigation, auto-downsampling beyond 2000 packets, hover/zoom, search & time-window highlight
- **报文详情**:帧 → L2 → L3 → L4 → 应用层分层折叠树 + hex dump
  **Packet detail**: layered collapsible tree (Frame → L2 → L3 → L4 → Application) + hex dump
- **多视角**:左侧栏 会话 / 主机(谁与谁通信最多、异常主机)/ 摘要(协议分布、异常类型、Top 主机)/ 拓扑(可拖拽,点击直达会话)四页切换
  **Multi-view**: Sessions / Hosts (top talkers, anomalies) / Summary (protocols, issue types, top hosts) / Topology (draggable, click-through)
- **时间分布下钻**:全局报文密度直方图,点击桶自动定位该时间窗内报文最多的会话并高亮窗口内报文
  **Time drill-down**: global traffic histogram; clicking a bucket auto-locates the busiest conversation and highlights its in-window packets
- **导出**:时序图 PNG(大图高度封顶防 OOM)+ Markdown 时序叙述(可直接贴进文档/周报)
  **Export**: sequence PNG (height-capped against OOM) + Markdown transcript
- **一体化 UI**:自绘标题栏、可拖拽并持久化面板尺寸、渲染错误显示可读错误而非白屏、三面板错误边界隔离
  **Integrated UI**: custom title bar, draggable & persisted panels, error boundaries instead of white screens
- **健壮性**:解析上/下限额(输入 128MB / JSON 64MB 前后端同档)、超大输出流式截断、子进程超时与 stderr 并发排空防死锁、命令异步化不冻结 UI、临时文件唯一化并退出清理、tshark 路径白名单校验、Windows 保留名/ADS/符号链接防御
  **Robustness**: input/output size budgets, stream caps, subprocess timeouts with stderr draining, async commands, temp-file hygiene and hardened tshark path validation

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
  **tshark** (Wireshark CLI) — resolved in order: user-set path → bundled resource → `PATH` → common install locations.
- **Rust**(cargo)与 **Node.js**(≥ 18),以及平台的 WebView2。
  **Rust** (cargo) and **Node.js** (≥ 18), plus the platform's WebView2.

## 🚀 构建与运行 / Build & Run

```bash
npm install

npm run tauri dev      # 开发模式(热更新) / development (HMR)
npm run tauri build    # 打包发布 / production bundle

npm test               # 前端测试(当前 162 用例)/ frontend tests
cargo test --manifest-path src-tauri/Cargo.toml   # Rust 测试(当前 16 用例)/ Rust tests
```

> 打包版为无控制台 GUI;子进程已加 `CREATE_NO_WINDOW`,不会闪现 cmd 窗口。
> The packaged app is a console-less GUI; child processes use `CREATE_NO_WINDOW` so no console windows flash.

## 📖 使用说明 / Usage

1. **打开**:工具栏「打开文件」或拖拽 pcap/pcapng;也可直接选择内置示例。
   **Open**: toolbar button, drag-and-drop, or built-in examples.
2. **筛选**:左侧筛选面板按协议/地址/端口、取反、仅看异常、异常类型与慢响应阈值。
   **Filter**: left panel — protocol / IP / port, negation, issues-only, issue types, slow-response threshold.
3. **浏览**:会话列表排序/搜索;右侧时序图:切换风格与时间戳、按段导航、点击报文看分层详情与 hex。
   **Browse**: sortable/searchable conversation list; sequence diagram with styles, timestamps, segment navigation; click packets for layered detail + hex.
4. **多视角**:左栏切 会话 / 主机 / 摘要 / 拓扑;摘要页的时间分布直方图点击桶即下钻定位。
   **Views**: switch Sessions / Hosts / Summary / Topology; click a histogram bucket in Summary to drill into a time window.
5. **导出**:右上「导出 PNG」保存时序图;「导出叙述」保存 Markdown 时间线。
   **Export**: "导出 PNG" for the diagram; "导出叙述" for a Markdown transcript.

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
  parse/         tshark JSON → Packet 模型 / tshark JSON → Packet model
  aggregate/     会话聚合 + 丢包检测 + 长会话分段 / aggregation + issues + segmentation
  filter/        筛选逻辑 / filtering
  search/        报文全文搜索 / packet full-text search
  stats/         主机统计 · 摘要统计 · 拓扑 · 时间直方图 / host/summary/topology/histogram
  render/        时序图布局与渲染 / sequence layout & rendering
  app/           布局 · 工具栏 · 筛选 · 列表 · 多视角面板 / layout, toolbar, filters, list, views
  detail/        报文分层详情 + hex / layered detail + hex
  export/        PNG 导出 + Markdown 叙述导出 / PNG & transcript export
  bridge/        Tauri IPC + 浏览器回退 / Tauri IPC + browser fallback
  state/         Zustand 全局状态(含派生过滤)/ global store & derived filtering
src-tauri/       Rust 后端(命令层 + tshark 进程管理 + 安全加固)/ Rust backend
public/fixtures 内置示例抓包 / built-in example captures
docs/            需求 · 架构 · 决策 · 实现计划 · 审查报告 / PRD · architecture · decisions · plan · review
scripts/         示例抓包与图标生成 / fixture & icon generators
```

## 📚 文档 / Docs

详见 [docs/README.md](docs/README.md)(产品需求、技术选型与架构、关键决策、实现计划、对抗审查报告)。
See [docs/README.md](docs/README.md) for the PRD, architecture, decisions, implementation plan and adversarial review.

---

*Built for packet-level troubleshooting & teaching. Bugs / ideas welcome.*