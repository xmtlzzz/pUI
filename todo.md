# pUI 项目状态 TODO

> 更新:2026-08-26 · 依据 `docs/specs/2026-08-25-pUI-报文分析能力升级计划.md`(M0-M7 路线)
> 产品目标:把 PCAP 中分散的报文,还原为可验证的网络故障事件和证据链 —— 观察与推断分离,不过度归因。

---

## 一、当前基线

| 项 | 值 |
|---|---|
| 前端测试 | 353+ 用例全绿(`npx vitest run`,50 文件;本轮重构后再跑一次全量确认) |
| Rust 测试 | 17 用例全绿(`cargo test --manifest-path src-tauri/Cargo.toml`) |
| 构建 | `npm run build` 通过(bundle gzip ≈123KB,含 gsap) |
| 技术栈 | React 19 + TS 5.8 strict + Zustand 5 + Vite 7 + Vitest 4 + Tauri 2 + tshark 4.6.6 + GSAP |
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

## 三、本轮重构(用户第二轮反馈,已完成待提交)

用户实测 VDI 抓包后的两条反馈:①左栏不应是数千行报文列表,要案例文档承诺的**序列空间图形化** + DSH duration 式**时间进度条**;②故障分析应**整页切换**而非右侧局部替换。

- [x] 视图模型重构:`card`(观察/推断/限制分层)+ `seqSpace`(轴聚焦缺口邻域、已见条/Gap/SACK 合并裁剪、ACK 轨迹、重传箭头)+ `keyPackets`(仅证据链报文)替代全量 `leftMessages`
- [x] `SeqSpaceGraphic`(SVG):刻度轴、已见字节条(绿)、Gap hatch(红斜纹)、SACK 绿块、重传回补箭头、ACK 游标(随播放推进)
- [x] 阶段带双形态:DSH 式总览条(彩色段+播放游标)+ 阶段卡片(名称/起止包号/时刻/要点常驻可见,点击联动信息面板)
- [x] 整页板块:进入故障分析时筛选/列表/时序/详情全部让位,「← 返回时序视图」恢复
- [x] 测试重构:viewModel 11 用例(序列空间数据含 SYN 字节、SACK 合并、单观察点语义)、组件 9 用例(图形元素级断言)、AppLayout 整页切换集成断言

## 四、M4 剩余(未做,按优先级)

- [ ] **GSAP 元素级分镜动画**:案例分镜 S1-S8 中的报文飞入、Gap 显露脉冲、SACK 逐块增长、重传回补弧线动画。当前播放只推进时间维(ACK 游标 + 时间带游标),信息已完整但无"过程感"
- [ ] **多事件会话**:当前只展示 `events[0]`;VDI 实测有大量缺口事件,需要事件列表/切换器(左栏顶部)
- [ ] **跳包后上下文恢复**:跳回报文详情后再返回,恢复此前选中事件与播放进度(案例 openQuestion 已裁定按分镜粒度)
- [ ] **报文详情侧入口**:报文详情中"查看事件上下文"(当前只有会话头按钮入口)
- [ ] **s2c 方向序列空间**:图形只画事件方向;双向流缺对向视图
- [ ] **窄窗口双标签**:案例文档要求 <900px 双标签切换,当前实现为纵向堆叠(可读但未按案例)
- [ ] **Tauri 桌面冒烟**:真实 VDI 抓包全流程(打开→会话→故障分析→播放/暂停/单步→跳包→返回)
- [ ] 导出(PNG/叙述)与对照页的关系(对照页是否可导出/不入报告证据的口径确认)

## 五、未开工(按计划 M5-M7)

**M5 分析增强(非 MVP)** —— 每项可独立关闭:
- [ ] Zero/Full Window、RST、连接建立、SYN 重传事件
- [ ] RTT 分位数/variation、窗口变化、完整 Capture Quality(截断/丢包统计)
- [ ] 完整 Sequence Space View(缩放/筛选,当前仅缺口邻域)
- [ ] Health Score(透明版本化公式+扣分明细,仅筛选用,覆盖不足显示 unavailable)
- [ ] 性能:10 万包 Worker 化解析、tshark 分批/流式、事件虚拟化

**M6 业务体验关联**:
- [ ] `ApplicationAnalyzer` 插件接口;第一批 HTTP/DNS/TLS(复用现有字段,不声明解密)
- [ ] `ApplicationImpact`:时间窗+阶段重叠关联,措辞限定"相关/可能影响"
- [ ] 第二批 SSH/RDP/VNC/SMB 单独审批字段与规则

**M7 证据化报告(最后)**:
- [ ] 版本化 JSON(Evidence schema)/ 分析 Markdown / 离线单文件 HTML(全转义、无远程资源)
- [ ] 语义一致性与确定性快照测试;恶意内容注入防护测试

## 六、已知问题 / 技术债

- [ ] **bundle 体积**:gsap 使主 chunk 增至 ~123KB gzip;可懒加载(动态 import)或按需迁移到 WAAPI
- [ ] **FaultCompare 单文件偏大**(~400 行):可拆 SeqSpaceGraphic/StageBand/EventCard 子组件
- [ ] **CI 缺位**:全部门槛本地手跑;建议 GitHub Actions/本地 pre-push 钩子跑 vitest+build+cargo
- [ ] **解析主线程**:>10 万包 tshark JSON 前端 parse 在主线程(128MB 守卫内可能秒级卡顿)——M5 Worker 化前置
- [ ] **计划文档状态表**:M4 行已更新(本轮),后续里程碑完成时需同步维护
- [ ] seqSpace 的 `ackTrack` 每次 build 全量扫描 packets(单会话 O(n),VDI 规模无感;Worker 化后自然消解)

## 七、验证命令

```bash
npx vitest run                                        # 前端全量
npm run build                                         # tsc strict + vite
cargo test --manifest-path src-tauri/Cargo.toml       # Rust 侧
npx vitest run src/analysis/tcp/perfGuard.test.ts    # 性能护栏(无 tshark 时自动跳过 e2e)
```

桌面冒烟(待 M4 剩余项完成后执行):打开 PCAP → 选会话 → 故障分析(整页)→ 播放/暂停/单步 → 阶段卡点选 → 关键报文跳包 → 返回时序视图。

## 八、关键设计约束(实现时不可违背)

1. **不过度归因**:标签≠结论;观察/推断/限制分层;单观察点限制必须随事件展示;byteCount 缺失显示 unknown 不显示 0
2. **右栏正常参考是示意**:固定徽标、无真实包号、永不进入观察/证据/导出
3. **阶段标注常驻**:阶段名/起止包号/要点不允许只藏在 hover 或 tooltip
4. **动画不承载唯一信息**:可暂停/单步/中断;reduced-motion 信息等价;transform/opacity 零布局回流
5. **确定性**:同输入同输出(event id、阶段序列、快照);分析纯函数,派生数据不入 store
6. **性能护栏**:风暴 <3s;SACK 渲染 ≤100 块;列表只放证据链报文
