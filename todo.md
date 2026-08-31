# pUI 项目状态 TODO

> 更新:2026-08-31(第 11 次,可选项清零 + 格式扩展) · 依据 `docs/specs/2026-08-25-pUI-报文分析能力升级计划.md`(M0-M7 路线)
> 产品目标:把 PCAP 中分散的报文,还原为可验证的网络故障事件和证据链 —— 观察与推断分离,不过度归因。

---

## 一、当前基线

| 项 | 值 |
|---|---|
| 前端测试 | 593 用例全绿(`npx vitest run`,70 文件) |
| Rust 测试 | 25 用例全绿(`cargo test --manifest-path src-tauri/Cargo.toml`,含真实 tshark e2e) |
| 示例抓包 | http/dns/mixed/lossy/**remote**(remote=SSH/VNC/RDP/SMB2 四协议演示,gen-fixtures 可复现) |
| 打开格式 | pcap/pcapng/cap/dmp/gz(透明解压)/5views/NetMon/nettl/snoop/CommView/Sniffer/ERF/btsnoop 等(tshark 按内容魔数识别,实测锚点 e2eFlat) |
| 构建 | `npm run build` 通过(主 chunk gzip ≈117KB;docx 为懒加载 chunk ≈119KB gzip,仅导出 Word 时加载) |
| 技术栈 | React 19 + TS 5.8 strict + Zustand 5 + Vite 7 + Vitest 4 + Tauri 2 + tshark 4.6.6(GSAP 已随播放功能移除) |
| 性能护栏 | 5000 段重传风暴(~1.5 万包/100 缺口)分析 <3s(`perfGuard.test.ts`) |

## 二、已完成(全部已提交)

| 里程碑 | 提交 | 内容 |
|---|---|---|
| **M0 事实契约** | `97ab20a` | 字段契约 33→41(`tcp.stream`/`tcp.len`/SACK 边界/`completeness`/`cap_len` 等),三处同步契约测试;**raw 序号空间**(`-o tcp.relative_sequence_numbers:FALSE`,消除 SACK 相对/原始混用的假 Gap);SACK 并行数组逐对 zip;dup-ack 标签按报文去重;parsed fixture 重生成 |
| **M2 序列空间引擎** | `69d1e88` | RFC1982 32 位序号算术;区间集(展开绝对坐标);逐方向序列跟踪;Gap 完整生命周期(暴露/SACK 覆盖/填补/存续时长);段分类六态;SYN/FIN 消耗;mid-stream 判定(completeness 位掩码);真实 tshark 端到端 5 场景;变异验证测试有效性 |
| **M3 事件引擎** | `336299e` | 三类 MVP 事件(疑似丢失/延迟、乱序、疑似 ACK 丢失/伪重传);`classifyFill` 显式规则表(信号/置信度/理由记录在事件上);证据链 observations/inference/limitations 分层;确定性 event id;未恢复优先排序 |
| **M1 可信度修正** | `be650d5` | 会话身份纳入 `tcp.stream`(同端点多连接不再错并);全部用户可见文案分离观察/推断,消除"重传→可能丢包"式过度归因;issue type 保持兼容 |
| **对抗审计修复** | `0457147` | 4 路攻击独立复现的 5 个缺陷:候选带放置(外来 ISN 幻影空洞)、seqCmp 反对称性、部分填补重复记账、回绕流 Gap 排序(startAbs)、判别魔法数重构 |
| **M4 案例与审批** | `0420c8a` `9af85ec` | 三份故障/正常对照案例文档 + 冻结数据快照(22 项数字保真核验);审批通过,附**阶段标注强化要求**(已写入案例审批记录节) |
| **M4 阶段推导基座** | `9af85ec` | `deriveStages`:从事件证据链确定性推导命名故障阶段(缺口类 5 阶段/伪重传 4 阶段含静默窗),纯函数 + 单测 |
| **M4 对照页 v1** | `4753557` | 视图模型层 / usePlayback(GSAP 只补间时间值,DOM 声明式) / FaultCompare 组件 / appStore+AppLayout 接线;阶段带、角色标注、九态交互、降级横幅、reduced-motion |
| **VDI 卡死修复** | `ab0c9a2` | 三处复杂度爆炸(segments.find O(gaps×n²)、对账 O(k²)、填补报文重复报告)→ 索引+窗口二分+双指针归并+coveredByGapEvent 集合;播放 reduced-motion 静默失败 → 显式解释+覆盖按钮+静态遍历 |
| **对照页重构(第二轮反馈)** | `f3851dd` | 序列空间图形化(SeqSpaceGraphic SVG)、DSH 式时间进度条阶段带、整页板块切换、keyPackets 仅证据链报文 |
| **多事件切换器** | `2604334` | 左栏顶部事件列表(kindLabel/缺口/未恢复徽标/时刻/严重度,限高滚动);buildEventSummaries 保持引擎"未恢复优先"序;compareEventIndex 入 store,切事件以 eventKey 重挂载复位播放 |
| **元素级分镜动画** | `268b0b6` | StoryboardMarks(证据链报文时刻→登场时刻纯函数)+ windowProgress/popIn;Gap 弹跳显露、SACK 块序增长、重传画线、恢复脉冲;GSAP 仍是唯一时钟,元素状态声明式推导;静态模式信息等价 |
| **跳包恢复+详情入口** | `7527f2e` | compareResume(事件+阶段粒度)记录/消费;「↩ 返回故障分析(事件 N · 阶段 M)」按钮;usePlayback 初始时刻=恢复即暂停;报文详情「查看事件上下文」惰性分析直达对应事件 |
| **切换卡顿+阶段带标注(第三轮反馈)** | `f95746d` | 会话级 facts/事件表缓存 + 事件级 vm 缓存(切换只剩毫秒级投影);阶段带内嵌「序号. 阶段名」常驻标注;序列空间图例与「序列号空间(字节)」轴说明 |
| **UI 统一+对向视图+双标签(第四轮反馈/M4 收尾)** | `20f268a` | 全部按钮接入主界面 .btn/.primary/.seg 设计语言;对向序列空间(静态全景,SACK/ACK 按方向过滤防双 ISN 混轴,单向流隐藏);窄窗 <900px 双标签切换实际故障/正常参考 |
| **对照页证据导出(M4 最后一项,口径已裁定)** | `e4ec53a` | exportCompareReport:实际故障侧证据导出(观察/推断/限制/阶段/关键报文链/降级说明),正常参考示意永不进入;顺带修复 mdCell 反引号/竖线转义静默失效(字面量 '\`' 实际只是反引号,exportTranscript 一并修复) |
| **M5 起步:新事件检测器** | `c316163` `2cb4a7d` | m5Events(与 M3 解耦,每项独立开关):零窗口/窗口耗尽/RST/SYN 重传,观察推断分离红线延续;tcp.window_size 字段契约三处同步(41→42 字段)+ fixture 再生成;零窗口接入会话标注与筛选(「零窗口」筛选项) |
| **M5 第二批:测量与采集质量** | `3a2cbaf` | SYN 重传接入会话标注(与 syn-no-reply 互补);rttStats(p50/p90/max,Karn 首次发送归属,样本<5 显式 unavailable);captureQuality(截断计数/比例,采集侧信号红线);SummaryPanel「会话测量」区;perfGuard 预算并发自适应消抖动 |
| **M5 第三批:窗口统计+Health Score** | `b3213a4` `1e13ab0` | windowStats(通告沿 min/max/变化次数/零窗口期数,接入摘要);Health Score v1(透明扣分明细:unrecovered-gap/rst/zero-window/truncated/retransmissions,仅筛选用标注,非 TCP unavailable) |
| **对抗审查修复(文案=证据)** | `5d6be84` | 审计+红队双 subagent 确认 20+4 项:观察层只写可观测事实(全新字节填补不再称"重发")、tshark 标签条件化不虚构、伪重传硬编码 0、填补者按本事件缺口定位、序列空间主视图方向过滤(双向随机 ISN 混轴/ACK 回跳)、方向锚点与分析层统一、导出缺口清单取全量不缺报、上下文/恢复下标被 openCompare 覆盖、severity/confidence 中文化等 |
| **2026-08-29 交互收尾** | `75888dc` `9332e49` | 启动过渡动画固定展示 2 秒(bootTiming);故障对照页播放功能按用户要求整体移除(删 usePlayback/GSAP 依赖,序列空间改静态终态:Gap/SACK/重传箭头满量直出,ACK 游标驻留最终累计确认位置),阶段浏览靠阶段卡点选,跳包恢复不变 |
| **报告导出 md/word/pdf** | `5046b27` | 会话级报告同一模型三格式(export/report/:reportModel 纯函数 + renderReportMd/Html/Docx);工具栏「格式选择+导出报告」替代导出叙述,紧凑叙述/仅异常包透传时序章节;PDF 走 ReportPreview 打印预览(WebView 原生打印存 PDF,系统字体矢量中文);Word 用 docx 动态 import;Rust 新增 save_bytes 通用二进制导出;报告模块由 subagent TDD 构建(51 用例) |
| **M7 最后一项:离线 HTML + CI** | `16a5db3` `63251cc` | evidenceHtml 事件级离线单文件报告(与 MD/JSON 同口径,全实体转义,零脚本零远程资源,打印 CSS,13 测,subagent 构建);FaultCompare「导出 HTML」按钮;CI 补位(GitHub Actions windows + .githooks/pre-push,已启用 core.hooksPath) |
| **可选项清零 + .cap 格式扩展** | `2044975` `5b7bc99` `d9c1b2b` `2d0be6e` | 打开格式全清单(.cap/.cap.gz 实测 e2e 三例一致,tshark 按魔数识别与扩展名无关);fetch_hex 流式化(run_hex_streaming+共享读循环,hex 上限 32MB→4MB,真实 tshark e2e);Worker 池化(并发解析,池=min(4,availableParallelism),requestId 关联防串扰,崩溃回落+重建);FaultCompare 拆出 StageBand/EventCard(919 行,44 断言零修改全绿) |
| **M6 第二批:SSH/RDP/VNC/SMB** | `038023c` | 8 字段契约三处同步(实测 tshark 4.6.6 核实;gen-parsed 正则大写感知,camelCase 注册名不再漏抓);4 分析器插件(SSH 横幅/通道、RDP 协商位掩码 0x1SSL/0x2CredSSP/0x4RDSTLS/0x8CredSSP扩展、VNC RFB 版本、SMB2 命令+请求响应+树路径);加密边界红线:只观察明文握手/命令;演示抓包 remote.pcapng;SummaryPanel 会话类别显示 |
| **M5 第四批:完整序列空间视图** | 本次 | panorama 全景视图(事件方向全字节轴,回绕流降级);clipSeqSpaceView/zoomStep 纯函数(裁剪/步进,确定性);+/−/重置按钮+滚轮指针锚点缩放+拖拽平移;图例升级为图层开关(已见/未收到/SACK/重传);切范围自动复位缩放 |

## 三、M4 已全部完成,进入 M5

M4 收尾状态(2026-08-27):
- [x] 导出口径已裁定并实现:对照页实际故障侧=证据可导出(工具条「导出报告」);正常参考=示意永不导出
- [x] **Tauri 桌面冒烟**:2026-08-29 实机完成(打开示例→选会话→故障分析→阶段卡点选→关键报文跳包→详情→「返回故障分析」事件+阶段还原→返回时序视图;PDF 打印预览实机走通;播放/暂停/单步已随播放功能移除不再适用)

M5 剩余(按优先级):
- [x] SYN 重传/RST/零窗口接入会话标注;RTT 分位数;Capture Quality;窗口变化统计
- [x] Health Score(health-v1 透明公式+扣分明细,仅筛选用)
- [x] 完整 Sequence Space View(缩放/筛选):全景+缺口邻域双模式,滚轮/按钮缩放、拖拽平移,图例即图层开关
- [x] 性能(第一批):10 万包主线程卡顿的根因(JSON.parse+字段投影)Worker 化 —— parseWorker+parseAsync 调度层(<1MB 主线程直解/≥1MB 走 Worker/失败回落),bridge 三入口接入;方向控件端点箭头化+事件轨图钉点击定位报文;SACK 紫色区分;ACK 游标自解释
- [x] 性能(第二批):tshark 流式分批 —— Rust run_capture_stream 按帧边界切批(~4MB/批)经 tauri ipc::Channel 增量回传,open_capture/open_capture_data 返回不再含整段 JSON;前端逐批投影(parsePacketsBatchPush,帧号跨批累计),解析期间工具条实时显示已解析帧数;事件切换器列表虚拟化(>60 事件只渲染可视区,数千事件不再全量挂载)
- [x] 性能(可选收尾,2026-08-31 启用):fetch_hex 流式化(run_hex_streaming,4MB 上限);Worker 池化(并发解析,min(4,availableParallelism))

## 四、未开工(按计划 M5-M7)

**M5 分析增强(非 MVP)** —— 每项可独立关闭:
- [x] Zero/Full Window、RST、SYN 重传事件检测器(m5Events;UI 接入:零窗口已接会话标注/筛选,RST 复用既有 rst 类型)
- [x] RTT 分位数/variation、窗口变化、Capture Quality(截断统计;丢包统计受单观察点限制不做断言)
- [x] 完整 Sequence Space View(缩放/筛选):全景视图(panorama,回绕流降级隐藏)+ clipSeqSpaceView/zoomStep 纯函数缩放;控件 +/−/重置、滚轮以指针为锚缩放、拖拽平移;图例升级为图层开关(已见/未收到/SACK/重传)
- [x] Health Score(透明版本化公式+扣分明细,仅筛选用,覆盖不足显示 unavailable)
- [ ] 性能:10 万包 Worker 化解析、tshark 分批/流式、事件虚拟化

**M6 业务体验关联(全部完成)**:
- [x] `ApplicationAnalyzer` 插件接口;第一批 HTTP/DNS/TLS(复用现有字段,不声明解密);摘要面板应用层事件区+慢响应下钻
- [x] `ApplicationImpact`:±2s 时间窗关联(每 TCP 事件只消费一次),限定措辞"同期现象,可能相关,不构成因果";接入对照页「同期应用层事件」块(点击跳包)与 Markdown/JSON 两份导出
- [x] 第二批 SSH/RDP/VNC/SMB:字段契约 + 4 分析器已落地(用户批准 2026-08-29;字段名经本机 tshark 实测核实;演示示例 remote)

**M7 证据化报告(全部完成)**:
- [x] 分析 Markdown(exportCompareReport,M4 已落地;M6 增应用层关联节)
- [x] 版本化 JSON 证据(schema pui-evidence/evidence-v1,evidenceReport;确定性+< 注入加固+13 测)
- [x] 离线单文件 HTML(evidenceHtml,与 MD/JSON 同口径;全转义/零脚本/零远程资源/打印 CSS)
- [x] 确定性快照测试(逐字节一致)与注入防护测试;语义一致性由既有 issueWording/红线测试网覆盖,HTML 导出落地时再补专项

## 五、已知问题 / 技术债

- [x] **bundle 体积**:gsap 已随播放功能移除删除(主 chunk ~127KB→~117KB gzip);新增 docx 为动态 import 懒加载 chunk,仅导出 Word 时加载,不进首屏
- [x] **FaultCompare 单文件偏大**:已拆出 SeqSpaceGraphic/StageBand/EventCard 子组件(919 行,编排聚焦)
- [x] **CI 缺位**:GitHub Actions(win: vitest+build+cargo test)+ .githooks/pre-push(同源门槛,已启用 core.hooksPath)
- [x] **解析主线程**:`parseAsync` 调度层已落地(<1MB 主线程直解,≥1MB 走 parseWorker,失败自动回落);Rust 侧 tshark 分批/流式仍在第二批
- [ ] seqSpace 的 `ackTrack` 每次 build 全量扫描 packets(单会话 O(n),VDI 规模无感;Worker 化后自然消解)
- [ ] 报文详情「查看事件上下文」点击时同步运行 analyzeStream+detectTcpEvents(有 perfGuard 护栏;若 VDI 会话点击感到顿挫,可在后台异步后跳转)

## 六、验证命令

```bash
npx vitest run                                        # 前端全量
npm run build                                         # tsc strict + vite
cargo test --manifest-path src-tauri/Cargo.toml       # Rust 侧
npx vitest run src/analysis/tcp/perfGuard.test.ts    # 性能护栏(无 tshark 时自动跳过 e2e)
```

桌面冒烟:2026-08-29 已实机走通(打开示例→选会话→故障分析→阶段卡点选→关键报文跳包→详情→「返回故障分析」事件+阶段还原→返回时序视图;PDF 打印预览)。播放/暂停/单步已随播放功能移除,不再适用。路线图 M0-M7 全部落地:M6 第二批已实现(演示示例 remote 覆盖 SSH/VNC/RDP/SMB2);可选项(fetch_hex 流式化/Worker 池化/FaultCompare 拆分)已于 2026-08-31 全部启用;打开格式扩展至现网常见全清单(.cap 等,按内容识别)。

## 七、关键设计约束(实现时不可违背)

1. **不过度归因**:标签≠结论;观察/推断/限制分层;单观察点限制必须随事件展示;byteCount 缺失显示 unknown 不显示 0
2. **右栏正常参考是示意**:固定徽标、无真实包号、永不进入观察/证据/导出
3. **阶段标注常驻**:阶段名/起止包号/要点不允许只藏在 hover 或 tooltip
4. **动画不承载唯一信息**:可暂停/单步/中断;reduced-motion 信息等价(分镜元素静态直出终态);transform/opacity 零布局回流
5. **确定性**:同输入同输出(event id、阶段序列、分镜标记、快照);分析纯函数,派生数据不入 store(仅导航性 UI 状态除外:compareFor/compareEventIndex/compareResume)
6. **性能护栏**:风暴 <3s;SACK 渲染 ≤100 块;列表只放证据链报文
