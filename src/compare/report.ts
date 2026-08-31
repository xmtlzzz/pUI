import type { AlignmentResult } from './align'
import type { ConversationDiff, EventDiffEntry, PacketDiffStats, TimelineRow } from './diff'
import type { VerdictEntry } from './verdict'

/**
 * 双观测点对照报告模型 —— 单一事实源(与 src/export/report/reportModel.ts 同风格):
 * 渲染器(Markdown / HTML)只做形态转换不做业务计算。
 *
 * 口径:
 * - **确定性**:纯函数,不内嵌时间戳 —— 同一输入两次构建逐字一致(取证可复现);
 * - **对齐层输入**:alignment 来自 alignConversations,diffs/verdicts 由主线程按
 *   AlignedPair 逐对调用 diffConversations/buildVerdicts 后以会话 id 为键传入 ——
 *   报告层不重复计算,只组织;
 * - **红线**:结论措辞已在 verdict 层限定为观察层,报告只透传;methodology 是
 *   固定口径文字(时间基/容差/不过度归因),防止报告脱离语境被断章取义。
 */

export interface CompareReportInput {
  /** A 侧抓包文件名(调用方注入,不来自解析结果) */
  fileA: string
  /** B 侧抓包文件名 */
  fileB: string
  /** 对齐结果(alignConversations 输出) */
  alignment: AlignmentResult
  /** 每对会话的差异模型,键 = A 侧会话 id */
  diffs: Map<string, ConversationDiff>
  /** 每对会话的结论条目,键 = A 侧会话 id */
  verdicts: Map<string, VerdictEntry[]>
}

/** 概要事实行(label/value 纯文本,渲染器自行转义) */
export interface ReportFact {
  label: string
  value: string
}

/** 报文计数/字节对照行 */
export interface ReportStatsRow {
  /** 会话对标识(A id ↔ B id) */
  label: string
  stats: PacketDiffStats
}

/** 事件差异表行(gapText 缺省归一为空串,渲染器按「无缺口」呈现) */
export interface ReportEventRow {
  kind: string
  gapText: string
  recovered: boolean
  onlyIn: 'A' | 'B' | 'both'
}

/** 未匹配会话行 */
export interface ReportUnmatchedRow {
  side: 'A' | 'B'
  /** 端点对展示(client → server) */
  label: string
  packetCount: number
}

/** 单对会话章节 */
export interface ComparePairSection {
  /** 端点对展示(client ↔ server,两侧同端点对故只用一份) */
  endpointLabel: string
  statsRow: ReportStatsRow
  eventRows: ReportEventRow[]
  verdicts: VerdictEntry[]
  timelineRows: TimelineRow[]
  /** 时间线是否被截断(diff 层 2000 行护栏) */
  timelineTruncated: boolean
}

export interface CompareReportModel {
  title: string
  summary: ReportFact[]
  pairs: ComparePairSection[]
  unmatchedRows: ReportUnmatchedRow[]
  /** 固定口径文字(时间基/容差/观察层红线) */
  methodology: string[]
}

/** 端点对展示标签(方向箭头仅表 client→server 的语义方向,不表抓包位置) */
function endpointLabelOf(pair: AlignmentResult['pairs'][number]): string {
  return `${pair.sideA.client} ↔ ${pair.sideA.server}`
}

/** 导出文件名:与 defaultEvidenceHtmlName 同风格(compare_<safe>.md/html);
 *  非 ASCII(中文/全角等)与文件系统危险字符统一压成下划线,保证跨平台可落盘 */
export function defaultCompareFileName(label: string, ext: 'md' | 'html'): string {
  const safe = label.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60)
  return `compare_${safe || 'report'}.${ext}`
}

export function buildCompareReport(input: CompareReportInput): CompareReportModel {
  const summary: ReportFact[] = [
    { label: 'A 侧文件', value: input.fileA },
    { label: 'B 侧文件', value: input.fileB },
    { label: '对齐会话对', value: String(input.alignment.pairs.length) },
  ]
  const bySide = { A: 0, B: 0 }
  for (const u of input.alignment.unmatched) bySide[u.side]++
  summary.push({
    label: '未匹配会话',
    value: `${input.alignment.unmatched.length}(A 侧 ${bySide.A} / B 侧 ${bySide.B})`,
  })

  const pairs: ComparePairSection[] = input.alignment.pairs.map((pair) => {
    const diff = input.diffs.get(pair.sideA.id)
    // diffs/verdicts 缺项:对齐结果与逐对分析由主线程同源生成,缺项属调用方契约破坏;
    // 这里退化为空模型而不是抛错 —— 报告导出应尽力而为,空章节比崩溃更符合取证场景
    const statsRow: ReportStatsRow = {
      label: `${pair.sideA.id} ↔ ${pair.sideB.id}`,
      stats: diff?.stats ?? { countA: 0, countB: 0, bytesA: 0, bytesB: 0 },
    }
    const eventRows: ReportEventRow[] = (diff?.eventDiffs ?? []).map((e: EventDiffEntry) => ({
      kind: e.kind,
      gapText: e.gapText ?? '',
      recovered: e.recovered,
      onlyIn: e.onlyIn,
    }))
    return {
      endpointLabel: endpointLabelOf(pair),
      statsRow,
      eventRows,
      verdicts: input.verdicts.get(pair.sideA.id) ?? [],
      timelineRows: diff?.timeline ?? [],
      timelineTruncated: diff?.truncated ?? false,
    }
  })

  const unmatchedRows: ReportUnmatchedRow[] = input.alignment.unmatched.map((u) => ({
    side: u.side,
    label: `${u.conv.client} → ${u.conv.server}`,
    packetCount: u.conv.packetCount,
  }))

  const methodology = [
    '时间基:所有时刻均为 frame.time_epoch 绝对秒;两侧各自的 relative 时间不可比,不用于对齐。',
    '同一交互「两侧均见」按 epoch 差 ≤ 2ms(可配)且方向相反判定;超出容差按各自单侧列出。',
    '两侧抓包各自独立分析,不合并字节/不重组序列空间;各侧漏包与时钟偏移由各自口径承担。',
    '结论仅为观察层提示,不构成对丢包位置或设备行为的断言。',
  ]

  return { title: '双观测点对照分析报告', summary, pairs, unmatchedRows, methodology }
}
