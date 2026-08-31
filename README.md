# pUI · 抓包报文时序分析

**pUI** 是一款跨平台(Win / macOS / Linux)桌面抓包分析工具,基于 Tauri 2 + React,以 Wireshark 的 `tshark` 为解析引擎。打开抓包后按协议/地址/端口/异常类型筛选,自动聚合双向会话,把报文交互渲染成带时间戳的时序图;在传统时序视图之上,内置 **TCP 字节流状态引擎**:从缺口/SACK/重传的证据链推导可解释的故障事件与阶段,观察与推断分层、不过度归因,并可导出 Markdown / Word / PDF / HTML 证据报告。

[English](README.en.md) · 简体中文

## ✨ 特性

### 会话分析主线

- **打开抓包**:pcap / pcapng / **cap**(tcpdump 与现网设备导出常见格式)及 gzip 压缩变体、5views / NetMon / nettl / snoop / CommView / Sniffer / ERF / btsnoop 等常见格式——tshark 按内容魔数识别,与扩展名无关;拖拽或对话框打开,内置 5 个示例;概览显示真实接口数、解析耗时与 tshark 版本
- **会话级筛选**:协议、源/目的 IP、源/目的端口,取反,仅看异常,并按异常类型细化(重传/乱序/重复ACK/丢段/零窗口/SYN重传/慢响应/未关闭/被重置/请求无响应/连接未建立/单向),慢响应阈值可调
- **双向会话聚合**:五元组归一化(含 `tcp.stream` 流身份)、自动判定客户端/服务端(IPv4 / IPv6 / MAC),中途接入/缺端口等畸形数据不致会话错分
- **时序图**:A 斜线 / B 行式双风格,相对/绝对时间戳,长会话按空闲间隔自动分段,>2000 报文自动抽稀降级,搜索/时间窗命中高亮
- **报文详情**:帧 → L2 → L3 → L4 → 应用层分层折叠树 + hex dump(单帧 hex 流式获取)
- **多视角**:会话 / 主机(Top 流量、异常主机)/ 摘要(协议分布、会话测量 RTT 分位数、窗口统计、健康分、应用层事件)/ 拓扑(可拖拽,点击直达会话)
- **时间分布下钻**:报文密度直方图,点击桶自动定位该时间窗最繁忙的会话

### TCP 故障分析(M0-M7 能力)

- **序列空间引擎**:RFC1982 32 位序号算术、raw 序号空间、SACK 并行数组逐对解析、缺口完整生命周期(暴露/覆盖/填补/存续)、mid-stream 判定
- **事件引擎**:疑似丢失/延迟、乱序、疑似 ACK 丢失/伪重传、零窗口、RST、SYN 重传——每类事件附证据链(观察/推断/限制三层)、确定性 id、未恢复优先排序
- **故障/正常对照页**:序列空间图形化(已见字节条、缺口斜纹、SACK 块、重传回补箭头、ACK 游标静态终态驻留)、缺口邻域/全景双视图、滚轮指针锚点缩放 + 拖拽平移、图例即图层开关、阶段带(每阶段名称/起止包号/时刻/要点常驻可见)、多事件切换器(>60 事件窗口虚拟化)、关键报文跳包与阶段恢复、同期应用层事件时间窗关联(限定措辞:可能相关,不构成因果)
- **应用层分析器**:HTTP / DNS / TLS / **SSH / RDP / VNC / SMB2** 插件式注册——加密协议只观察明文握手/命令字段,不重组、不解密
- **性能**:大文件走 Rust 帧边界流式分批(前端逐批解析、实时帧数进度);前端 JSON 解析 Worker 池化(并发解析,池大小 = min(4, CPU 核数));5000 段重传风暴(~1.5 万包)分析 <3s

### 报告与证据

- **会话报告三格式**:Markdown / Word(.docx,标准标题渐进排版)/ PDF(打印预览,WebView 原生打印存 PDF,系统字体矢量中文);「紧凑叙述」合并连续相同报文、「仅异常包」只列带标记报文
- **事件证据**:Markdown 报告 + 版本化 JSON 证据(schema `pui-evidence`,确定性输出)+ **离线单文件 HTML**(全实体转义、零脚本零远程资源、内联打印 CSS)——三种格式同一输入口径,语义一致
- **数据保真红线**:右栏「正常参考」是解释性示意,永不进入观察/证据/导出;byteCount 缺失显示 unknown,绝不以 0 冒充

## 🧱 技术栈

| 层 | 技术 |
|---|---|
| 桌面壳 | [Tauri 2](https://tauri.app/)(Rust) |
| 前端 | React 19 · TypeScript(strict)· Vite 7 · Zustand 5 |
| 解析引擎 | tshark(Wireshark CLI,4.6+ 实测) |
| 动画/文档 | 启动层 emotion-ball(官方引擎原样嵌入,见 NOTICE)· `docx` 懒加载 |
| 测试 | Vitest 4(593 用例)· Rust `cargo test`(25 用例,含真实 tshark e2e) |

## 📦 环境依赖

- **tshark**(Wireshark 命令行解析器)——按「用户设置路径 → 随包资源 → PATH → 常见安装目录」顺序查找;需安装 Wireshark 或在设置中指定 tshark 路径
- **Rust**(cargo)与 **Node.js**(≥ 18),以及平台的 WebView2

## 🚀 构建与运行

```bash
npm install

npm run tauri dev      # 开发模式(热更新)
npm run tauri build    # 打包发布(msi / nsis)

npm test               # 前端测试(当前 593 用例)
cargo test --manifest-path src-tauri/Cargo.toml   # Rust 测试(当前 25 用例)
npx vitest run src/analysis/tcp/perfGuard.test.ts # 性能护栏(无 tshark 自动跳过 e2e)
```

> 打包版为无控制台 GUI;子进程已加 `CREATE_NO_WINDOW`,不会闪现 cmd 窗口。
> CI:GitHub Actions(push/PR 跑 vitest + build + cargo test),本地 `.githooks/pre-push` 同源门槛(`git config core.hooksPath .githooks` 启用)。

## 📖 使用说明

1. **打开**:工具栏「打开文件」或拖拽抓包文件(cap/pcapng/pcap 及压缩变体均可);也可直接选择内置示例
2. **筛选**:左侧筛选面板按协议/地址/端口、取反、仅看异常、异常类型与慢响应阈值
3. **浏览**:会话列表排序/搜索;时序图切换风格与时间戳、按段导航;点击报文看分层详情与 hex
4. **故障分析**:选中会话后点「⚠ 故障分析」进入对照页——序列空间图形化、阶段带点选、关键报文跳包;报文详情「查看事件上下文」直达对应事件,返回时事件+阶段精确恢复
5. **导出**:时序图 PNG;会话报告(格式选择 Markdown / Word / PDF);对照页「导出报告 / 导出证据 JSON / 导出 HTML」
6. **多视角**:会话 / 主机 / 摘要 / 拓扑;摘要页直方图点击桶即下钻

## 🎯 内置示例

| 示例 | 内容 |
|---|---|
| `http` | 完整 HTTP 请求/响应(含 FIN 关闭) |
| `dns` | DNS 查询/响应 |
| `mixed` | ARP + DNS + HTTP 混合 |
| `lossy` | 丢包示例:重传 + 请求无应答(故障分析全流程演示) |
| `remote` | SSH / VNC / RDP / SMB2 四协议真实握手(应用层分析器演示) |

## 🗂️ 项目结构

```
src/             前端(React + Zustand)
  parse/         tshark JSON → Packet 模型(字段契约三处同步)
  analysis/      TCP 字节流引擎 · 事件引擎 · 阶段推导 · 应用层分析器
  aggregate/     会话聚合 + 异常标注
  m4/            对照页视图模型 · 缩放/动画纯函数
  render/        时序图布局与渲染
  app/           布局 · 工具栏 · 筛选 · 列表 · 多视角 · 故障对照页
  export/        PNG · 会话报告(md/docx/html)· 事件证据(md/json/html)
  bridge/        Tauri IPC + 浏览器回退
  state/         Zustand 全局状态
src-tauri/       Rust 后端(命令层 + tshark 进程管理 + 流式分批 + 安全加固)
public/fixtures  内置示例抓包
docs/            需求 · 架构 · 决策 · 实现计划 · 审查报告
scripts/         示例抓包与图标生成
```

## 📚 文档

详见 [docs/README.md](docs/README.md)(产品需求、技术选型与架构、关键决策、实现计划、对抗审查报告)。

## 📄 许可

[MIT](LICENSE)。第三方组件注意:`public/emotion-ball/` 内嵌的启动动画引擎与角色形象按上游声明仅限个人学习研究(商用需另行授权,详见该目录 NOTICE.md)。

---

*为包级排障与教学而做。欢迎 Issue / PR。*
