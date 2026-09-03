# pUI

Tauri + React 抓包分析工具:把 PCAP 中分散的报文还原为可验证的网络故障事件和证据链。
核心原则是**观察与推断分离、不过度归因**(详见 [todo.md 第七节「关键设计约束」](./todo.md))。

## 开发形式

按 TDD 开发:先写测试(红)→ 实现(绿)→ 重构。测试是行为契约,实现是对契约的满足。
可按需派发 subagent,但公共 API(已存在的导出函数/组件 props)不得破坏。

## 测试与验证命令

```bash
npx vitest run                                   # 前端全量(基线 ~774 用例;无 tshark 时 e2e 自动 skip)
npx vitest run src/stats/                        # 只跑统计层(纯函数,多数改动先跑这里)
npx vitest run src/app/SummaryPanel.test.tsx     # 摘要面板组件(jsdom)
npm run build                                    # tsc strict + vite 构建
cargo test --manifest-path src-tauri/Cargo.toml  # Rust 侧(tshark 桥)
```

提交/推送前必须通过:前后端全量测试 + `tsc strict` 类型检查 + 构建(本地 `.githooks/pre-push`
与 `.github/workflows/ci.yml` 同源门槛,已启用 `core.hooksPath`)。

## 目录地图

| 路径 | 职责 |
|---|---|
| `src/parse/` | tshark JSON 解析:字段契约 `captureFields.ts`、`parsePackets.ts`(平铺键优先/协议树回落)、Worker 化调度 `parseAsync.ts` |
| `src/analysis/tcp/` | TCP 序列空间引擎:`seq.ts`(RFC1982 序号算术)、`streamAnalysis.ts`(Gap 生命周期/段分类)、`events.ts`(M3 事件)、`m5Events.ts`(M5 新检测器)、`stages.ts`(故障阶段推导)、`scenarios.e2e.test.ts`(真实 tshark 端到端) |
| `src/analysis/app/` | 应用层插件分析器(HTTP/DNS/TLS/SSH/RDP/VNC/SMB2,只消费已解析字段) |
| `src/render/` | 时序图四种形态(斜线/行式/序号空间/时间流)与时间格式、布局纯函数 |
| `src/stats/` | 统计纯函数(全部无副作用、确定性):`summaryStats`/`histogram`(时间桶)/`throughputBuckets`(吞吐字节)/`rttStats`(RTT 分位数+对数桶)/`windowStats`(窗口通告统计+时间线)/`hostStats`/`topology`/`captureQuality`/`healthScore` |
| `src/app/` | 面板组件(Filter/List/Host/Summary/SequenceBoard/Topology/DualCompare) |
| `src/export/` | 报告导出:同一报告模型三格式(MD/HTML/Word) + 离线单文件 HTML + PNG |
| `src/bridge/` | Tauri 命令桥(无 Tauri 时回落浏览器 fixture 路径) |
| `src-tauri/src/` | Rust 侧:tshark 调用(`tshark.rs`)、命令(`commands.rs`)、`CAPTURE_FIELDS` 与 TS 契约三处同步 |
| `scripts/` | fixture 再生成(见下) |

## tshark 环境与 fixture

- 需要本机安装 tshark(Wireshark);无 tshark 时 `scenarios.e2e.test.ts`、`e2eFlat.test.ts`
  等真实抓包 e2e 用例**自动 skip**(`describe.skipIf`),不阻塞 CI。可用 `TSHARK` 环境变量指定路径。
- 示例抓包位于 `public/fixtures/examples/*.pcapng`(http/dns/mixed/lossy/remote/dual-a/dual-b)。
- 再生成脚本:
  - `scripts/gen-fixtures.mjs` → 合成 pcapng(纯字节构造,无需 tshark)。
  - `scripts/gen-parsed.mjs` → 用真实 tshark 把 pcapng 重新解析为 parsed JSON(字段清单
    用正则从 `captureFields.ts` 抓取,须与 Rust `CAPTURE_FIELDS` 一致;改字段契约后必须重跑)。
- 改动 tshark 字段契约时,`captureFields.ts` / Rust `CAPTURE_FIELDS` / `gen-parsed.mjs`
  三处必须同步,契约测试会钉住一致性。

## 关键设计红线(详见 todo.md 第七节)

1. **不过度归因**:标签≠结论;观察/推断/限制分层;单观察点限制必须随展示说明;字段缺失显示
   unavailable/unknown,不编造 0 或数字。
2. **确定性**:分析全部纯函数,同输入同输出;派生数据不入 store(仅导航性 UI 状态例外)。
3. **性能护栏**:风暴场景分析 <3s;大列表有抽稀/虚拟化护栏(见 todo.md)。
4. **正常参考永不进入证据/导出**(右栏对照页为示意)。

## git

每次操作完验证没问题符合需求之后,commit(提交前先跑上面「提交/推送前」的验证)。
