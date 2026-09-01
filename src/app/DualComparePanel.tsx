import { useMemo, useRef, useState } from 'react'
import { useApp } from '../state/appStore'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { alignConversations, type AlignedPair } from '../compare/align'
import { diffConversations, type ConversationDiff, type CompareTcpEvent } from '../compare/diff'
import { buildVerdicts, type VerdictEntry } from '../compare/verdict'
import { buildCompareReport, defaultCompareFileName } from '../compare/report'
import { renderCompareReportMd, renderCompareReportHtml } from '../compare/render'
import { analyzeStream } from '../analysis/tcp/streamAnalysis'
import { detectTcpEvents } from '../analysis/tcp/events'
import {
  detectZeroWindowEvents,
  detectFullWindowEvents,
  detectRstEvents,
  detectSynRetransmissionEvents,
  type M5Event,
} from '../analysis/tcp/m5Events'
import { runApplicationAnalyzers, type AppEvent } from '../analysis/app/analyzers'
import { saveText, isTauri } from '../bridge/tauri'
import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'
import './dualCompare.css'

/**
 * 双点对照面板(整页板块):主抓包(A 侧)+ 副抓包(B 侧)对照分析。
 *
 * 编排红线:两侧各自走完整分析链路(聚合 → 对齐 → 逐对分析 → 差异 → 结论),
 * 绝不跨侧合并字节/重组序列空间 —— 引擎(src/compare)已按此设计,本组件只编排。
 *
 * 性能红线:自动分析的预算上限 = 两侧包数合计 ≤ 30000(主线程单次编排 <1s 的护栏,
 * 与 AppLayout compareCache 同思路)。超预算的 pair 显示「点击分析」按钮,
 * 点击后单独分析并缓存(useState<Map>,不重跑)。
 */

/** 自动分析预算:两侧包数合计上限。超出则该 pair 需手动点击分析。 */
const AUTO_BUDGET = 30000

/** 示例清单:Toolbar 的 EXAMPLES 未导出(不动它的导出区),此处复制一份。
 *  dual-b 是双点对照的 B 侧演示数据(与 dual-a 同一条流、时钟快 1.5s);
 *  dual-a 也在列:便于从 B 侧视角反向对照(面板不限制两侧示例身份)。 */
const DUAL_EXAMPLES = ['http', 'dns', 'mixed', 'lossy', 'remote', 'dual-a', 'dual-b']

/** 单侧分析产物(事件三源合并 + facts)。
 *  事件元素类型用引擎窄接口的组合:detectTcpEvents/detect*M5Events/runApplicationAnalyzers
 *  的返回均与 CompareTcpEvent 结构兼容(TcpEvent/M5Event/AppEvent 携带 kind 等超集字段),
 *  联合类型即可直接传入 diffConversations 的 unknown[] 形参 —— 无需 Record 映射。 */
interface SideAnalysis {
  facts: ReturnType<typeof analyzeStream>
  events: Array<CompareTcpEvent | M5Event | AppEvent>
}

/** 单对会话的完整对照结果(缓存单元) */
interface PairAnalysis {
  diff: ConversationDiff
  verdicts: VerdictEntry[]
}

/** 逐对单侧分析:analyzeStream + detectTcpEvents + M5 四检出器 + 应用层分析器。
 *  三源事件合并传给 diffConversations(引擎按窄结构类型归一)。 */
function analyzeSide(conv: Conversation): SideAnalysis {
  const facts = analyzeStream(conv.packets)
  const tcpEvents = detectTcpEvents(facts, conv.packets)
  const m5 = [
    ...detectZeroWindowEvents(conv.packets),
    ...detectFullWindowEvents(conv.packets),
    ...detectRstEvents(conv.packets),
    ...detectSynRetransmissionEvents(conv.packets),
  ]
  const appEvents = runApplicationAnalyzers(conv.packets)
  // 三源合并为事件数组(引擎的 normalizeEvent 按结构分流,无需转换)
  return {
    facts,
    events: [...tcpEvents, ...m5, ...appEvents],
  }
}

interface DualComparePanelProps {
  onClose: () => void
}

export function DualComparePanel({ onClose }: DualComparePanelProps) {
  const meta = useApp((s) => s.meta)
  const conversations = useApp((s) => s.conversations)
  const dualMeta = useApp((s) => s.dualMeta)
  const dualPackets = useApp((s) => s.dualPackets)
  const dualLoading = useApp((s) => s.dualLoading)
  const dualLoadingFrames = useApp((s) => s.dualLoadingFrames)
  const dualError = useApp((s) => s.dualError)
  const openDualFile = useApp((s) => s.openDualFile)
  const openDualExample = useApp((s) => s.openDualExample)
  const clearDual = useApp((s) => s.clearDual)

  const inputRef = useRef<HTMLInputElement | null>(null)
  const pickFile = async () => {
    if (isTauri()) {
      // Tauri 2 须用原生对话框取真实路径(与 Toolbar pickFile 同模式)
      const { open: openDialog } = await import('@tauri-apps/plugin-dialog')
      const path = await openDialog({
        multiple: false,
        filters: [{ name: '抓包文件(pcap/pcapng/cap/gzip 等,全格式)', extensions: ['pcap', 'pcapng', 'cap', 'gz'] }],
      })
      if (typeof path === 'string') openDualFile(path)
    } else {
      inputRef.current?.click()
    }
  }

  // ---- 编排缓存:对齐结果按依赖(conversations/dualPackets)记忆化;
  //      引擎是纯函数,引用不变时不重跑 —— 与 AppLayout compareCache 同思路 ----
  const alignment = useMemo(() => {
    return alignConversations(conversations, dualPackets ? aggregateConversations(dualPackets) : [])
  }, [conversations, dualPackets])

  // 超预算 pair 的手动分析结果缓存(id = A 侧会话 id;组件级 state,换文件整页卸载自然重置)
  const [manualAnalyzed, setManualAnalyzed] = useState<Map<string, PairAnalysis>>(new Map())
  const [analysisTick, setAnalysisTick] = useState(0)

  /** 时钟偏移提示:A/B 首包 epoch 差(取第一对的两侧会话起点)。
   *  简单实现按任务规格:|convA.startEpoch - convB.startEpoch| —— 两侧抓包启动时刻
   *  之差包含真实偏移与抓包启动时差,只作「已按绝对秒对齐」的可读性提示。 */
  const clockOffsetHint = useMemo(() => {
    const first = alignment.pairs[0]
    if (!first) return null
    const ea = first.sideA.packets[0]?.timeEpoch
    const eb = first.sideB.packets[0]?.timeEpoch
    if (ea == null || eb == null) return null
    const off = eb - ea
    if (Math.abs(off) <= 0.002) return null // ≤ 2ms 视为无偏移
    return off
  }, [alignment])

  // 逐对惰性分析:预算内自动;超预算仅当用户点击后才分析(analysisTick 只是
  // 手动分析后的重算信号,真实数据源是 manualAnalyzed Map)
  const pairResults = useMemo(() => {
    void analysisTick
    const out: Array<{
      pair: AlignedPair
      result: PairAnalysis | null
      overBudget: boolean
    }> = []
    for (const pair of alignment.pairs) {
      const total = pair.sideA.packetCount + pair.sideB.packetCount
      if (total > AUTO_BUDGET) {
        const cached = manualAnalyzed.get(pair.sideA.id)
        out.push({ pair, result: cached ?? null, overBudget: cached == null })
        continue
      }
      out.push({ pair, result: analyzePair(pair), overBudget: false })
    }
    return out
  }, [alignment, manualAnalyzed, analysisTick])

  // 时间轴基准:A 侧首包 epoch(所有 epoch 显示为相对它的差值,原始 13 位数不裸奔)
  const baseEpochA = useMemo(() => {
    const c = conversations[0]
    return c?.packets[0]?.timeEpoch ?? null
  }, [conversations])

  const report = useMemo(() => {
    if (!meta) return null
    const diffs = new Map<string, ConversationDiff>()
    const verdicts = new Map<string, VerdictEntry[]>()
    for (const { pair, result } of pairResults) {
      if (!result) continue
      diffs.set(pair.sideA.id, result.diff)
      verdicts.set(pair.sideA.id, result.verdicts)
    }
    return buildCompareReport({
      fileA: meta.fileName,
      fileB: dualMeta?.fileName ?? '',
      alignment,
      diffs,
      verdicts,
    })
  }, [meta, alignment, pairResults])

  const onExport = async (ext: 'md' | 'html') => {
    if (!report) return
    try {
      const label = `双点对照 ${meta?.fileName ?? ''}`
      const text = ext === 'md' ? renderCompareReportMd(report) : renderCompareReportHtml(report)
      await saveText(defaultCompareFileName(label, ext), text, { name: ext.toUpperCase(), extensions: [ext] })
    } catch (err) {
      window.alert(err instanceof Error ? err.message : String(err))
    }
  }

  const analyzeManual = (pair: AlignedPair) => {
    setManualAnalyzed((prev) => {
      const next = new Map(prev)
      next.set(pair.sideA.id, analyzePair(pair))
      return next
    })
    setAnalysisTick((t) => t + 1)
  }

  const fmtEpoch = (t: number): string => {
    if (baseEpochA == null) return t.toFixed(3)
    return (t - baseEpochA).toFixed(3)
  }

  return (
    <div className="dc-page">
      <div className="dc-toolbar">
        <button type="button" className="btn" onClick={onClose} data-testid="dc-back">
          ← 返回
        </button>
        <span className="dc-headline">⇄ 双点对照</span>
        <button type="button" className="btn" onClick={pickFile} data-testid="dc-open-dual">
          打开 B 侧抓包
        </button>
        <select
          className="btn"
          defaultValue=""
          data-testid="dc-example-select"
          onChange={(e) => {
            if (e.target.value) openDualExample(e.target.value)
            e.target.value = ''
          }}
        >
          <option value="">B 侧示例…(推荐 dual-b 配 dual-a)</option>
          {DUAL_EXAMPLES.map((x) => (
            <option key={x} value={x}>
              {x}
            </option>
          ))}
        </select>
        {dualMeta && dualPackets && (
          <span className="dc-bmeta" data-testid="dc-bmeta">
            B 侧:{dualMeta.fileName}({dualMeta.packetCount.toLocaleString()} 包)
          </span>
        )}
        {dualLoading && (
          <span className="dc-loading" role="status" data-testid="dc-dual-loading">
            B 侧解析中… {dualLoadingFrames.toLocaleString()} 帧
          </span>
        )}
        {dualError && (
          <span className="dc-err" data-testid="dc-dual-error">
            {dualError}
          </span>
        )}
        <span style={{ flex: 1 }} />
        <button
          type="button"
          className="btn"
          data-testid="dc-export-md"
          disabled={!report || report.pairs.length === 0}
          onClick={() => onExport('md')}
        >
          导出对照报告 .md
        </button>
        <button
          type="button"
          className="btn"
          data-testid="dc-export-html"
          disabled={!report || report.pairs.length === 0}
          onClick={() => onExport('html')}
        >
          导出对照报告 .html
        </button>
        {dualPackets && (
          <button type="button" className="btn sm" onClick={() => clearDual()} title="移除 B 侧抓包">
            ✕ 移除 B 侧
          </button>
        )}
        {/* 文件选择器(浏览器回退路径):与 Toolbar 同款 input 模式 */}
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap,.gz"
          style={{ display: 'none' }}
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) openDualFile(f.name)
            e.target.value = ''
          }}
        />
      </div>

      {!dualPackets ? (
        <div className="dc-empty" data-testid="dc-empty">
          <p>B 侧抓包未加载:请打开同事在另一观测点抓取的文件。</p>
          <p className="dc-empty-sub">A 侧为当前主抓包;两侧各自独立分析,仅对齐与比较结论。</p>
        </div>
      ) : (
        <div className="dc-body">
          <div className="dc-summary" data-testid="dc-pairs-summary">
            对齐会话对 <strong>{alignment.pairs.length}</strong> · 未匹配{' '}
            <strong>{alignment.unmatched.length}</strong>
          </div>

          {alignment.unmatched.length > 0 && (
            <table className="dc-table" data-testid="dc-unmatched-table">
              <thead>
                <tr>
                  <th>侧</th>
                  <th>端点对</th>
                  <th>包数</th>
                </tr>
              </thead>
              <tbody>
                {alignment.unmatched.map((u, i) => (
                  <tr key={`${u.side}:${u.conv.id}:${i}`}>
                    <td>{u.side}</td>
                    <td>
                      {u.conv.client} → {u.conv.server}
                    </td>
                    <td>{u.conv.packetCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {pairResults.map(({ pair, result }, idx) => {
            const convAStart = pair.sideA.packets[0]?.timeEpoch
            const convBStart = pair.sideB.packets[0]?.timeEpoch
            const pairOffset = convAStart != null && convBStart != null ? convBStart - convAStart : null
            return (
              <section key={pair.sideA.id} className="dc-pair" data-testid="dc-pair-section">
                <h3 className="dc-pair-title">
                  会话对 {idx + 1}:{pair.sideA.client} ↔ {pair.sideA.server}
                  {pairOffsetSignificant(pairOffsetHint(pairOffset)) && clockOffsetHint != null && (
                    <span className="dc-clock-hint" data-testid="dc-clock-hint">
                      B 侧时钟偏移约 {clockOffsetHint >= 0 ? '+' : ''}
                      {clockOffsetHint.toFixed(3)}s(时间线已按绝对秒对齐)
                    </span>
                  )}
                </h3>
                {result ? (
                  <PairResultView
                    diff={result.diff}
                    verdicts={result.verdicts}
                    fmtEpoch={fmtEpoch}
                  />
                ) : (
                  <div>
                    <p className="dc-overbudget">会话对过大(两侧合计 {pair.sideA.packetCount + pair.sideB.packetCount} 包,超出自动分析预算),点击分析。</p>
                    <button
                      type="button"
                      className="btn"
                      data-testid="dc-analyze-manual"
                      onClick={() => analyzeManual(pair)}
                    >
                      点击分析
                    </button>
                  </div>
                )}
              </section>
            )
          })}
        </div>
      )}
    </div>
  )
}

/** 会话对偏移超过 2ms 视为「有偏移」(与 diff 默认容差同源) */
function pairOffsetSignificant(off: number): boolean {
  return Math.abs(off) > 0.002
}
function pairOffsetHint(off: number | null): number {
  return off ?? 0
}

/** 单对结果展示(stats/事件差异/结论/时间线) */
function PairResultView({
  diff,
  verdicts,
  fmtEpoch,
}: {
  diff: ConversationDiff
  verdicts: VerdictEntry[]
  fmtEpoch: (t: number) => string
}) {
  const s = diff.stats
  return (
    <div>
      <table className="dc-table" data-testid="dc-pair-stats">
        <thead>
          <tr>
            <th>指标</th>
            <th>A 侧</th>
            <th>B 侧</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>包数</td>
            <td>{s.countA}</td>
            <td>{s.countB}</td>
          </tr>
          <tr>
            <td>字节</td>
            <td>{s.bytesA}</td>
            <td>{s.bytesB}</td>
          </tr>
        </tbody>
      </table>

      <h4>事件差异</h4>
      {diff.eventDiffs.length === 0 ? (
        <p className="dc-none">无事件差异。</p>
      ) : (
        <table className="dc-table" data-testid="dc-eventdiff-table">
          <thead>
            <tr>
              <th>事件类型</th>
              <th>缺口区间</th>
              <th>恢复状态</th>
              <th>出现侧</th>
            </tr>
          </thead>
          <tbody>
            {diff.eventDiffs.map((e, i) => (
              <tr key={`${e.kind}:${e.gapText ?? ''}:${i}`} data-testid="dc-event-row">
                <td>{e.kind}</td>
                <td>{e.gapText ?? '—'}</td>
                <td>{e.recovered ? '已恢复' : '未恢复'}</td>
                <td>{e.onlyIn === 'A' ? '仅 A' : e.onlyIn === 'B' ? '仅 B' : '两侧'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h4>结论辅助(观察层提示)</h4>
      {verdicts.length === 0 ? (
        <p className="dc-none">无。</p>
      ) : (
        <ul className="dc-verdicts" data-testid="dc-verdicts">
          {verdicts.map((v, i) => (
            <li key={i} className={v.severity === 'warn' ? 'dc-warn' : 'dc-info'} data-testid="dc-verdict-row">
              {v.statement}
            </li>
          ))}
        </ul>
      )}

      <h4>时间线{diff.truncated ? '(已截断:仅保留最早部分)' : ''}</h4>
      {diff.timeline.length === 0 ? (
        <p className="dc-none">无可列报文。</p>
      ) : (
        <table className="dc-table" data-testid="dc-timeline-table">
          <thead>
            <tr>
              <th>时刻 (s)</th>
              <th>观测</th>
              <th>A #</th>
              <th>A 信息</th>
              <th>B #</th>
              <th>B 信息</th>
            </tr>
          </thead>
          <tbody>
            {diff.timeline.map((r, i) => (
              <tr key={i} data-testid="dc-tl-row">
                <td>{fmtEpoch(r.timeEpoch)}</td>
                <td>
                  <span className={r.side === 'AB' ? 'dc-badge ab' : r.side === 'A' ? 'dc-badge a' : 'dc-badge b'}>
                    {r.side}
                  </span>
                </td>
                <td>{r.numberA != null ? `#${r.numberA}` : '—'}</td>
                <td>{r.infoA ?? '—'}</td>
                <td>{r.numberB != null ? `#${r.numberB}` : '—'}</td>
                <td>{r.infoB ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

/** 单对分析:两侧独立走完整链路,diff 只消费结论(绝不跨侧合并字节)。
 *  端点身份传给 verdict:把事件方向(c2s/s2c)翻译成「客户端→服务端」等
 *  显式路径措辞 —— 与引擎的时钟偏移口径一致(客户端侧见缺口 = 客户端发出的
 *  数据在到达该观测点前丢失)。 */
function analyzePair(pair: AlignedPair): PairAnalysis {
  const a = analyzeSide(pair.sideA)
  const b = analyzeSide(pair.sideB)
  const diff = diffConversations(
    pair.sideA,
    a.facts,
    a.events,
    pair.sideB,
    b.facts,
    b.events,
  )
  return {
    diff,
    verdicts: buildVerdicts(diff, {
      client: displayHost(pair.sideA.client),
      server: displayHost(pair.sideA.server),
    }),
  }
}
