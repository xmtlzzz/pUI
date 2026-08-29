import type { Conversation } from '../../model/types'
import { displayHost } from '../../model/types'
import { transcriptTableLines } from '../exportTranscript'

/**
 * 会话分析报告模型 —— 单一事实源,渲染器(Markdown / DOCX / HTML)只做形态转换不做业务计算。
 *
 * 口径(与 evidenceReport / exportCompareReport 同风格):
 * - **确定性**:纯函数,同输入同输出;不内嵌 Date.now/new Date,生成时间由调用方经
 *   ReportOptions.generatedAt 注入,缺省 null 时各渲染器省略「生成时间」行(有测试钉住);
 * - **复用**:「三、会话时序」直接承载 transcriptTableLines 的原样输出(表头/分隔/数据行),
 *   紧凑与仅异常的语义与叙述导出完全一致,不另写一份合并/过滤逻辑;
 * - **分层措辞**:「四、证据口径与限制」为固定口径文字(观察/推断分层、单观察点限制),
 *   观察是抓包中直接可见的现象,推断不构成根因断言 —— 与对照页报告同一红线。
 */

/** 报告渲染选项(与叙述导出的勾选项同语义) */
export interface ReportOptions {
  /** 紧凑区间:连续相同报文合并为一行区间,防巨大会话文档卡顿 */
  compact?: boolean | null
  /** 仅异常包:只保留带 TCP 分析标记的报文(周报口径) */
  anomalies?: boolean
  /** 生成时间(调用方注入以保证确定性);缺省/null 时报告省略该行 */
  generatedAt?: string | null
}

/** 章节/小节标题(中文,渐进层级:一级章节「一~四」,其下小节为二级)。
 *  放常量的原因:三个渲染器必须共用同一套标题文案,避免文案漂移。 */
export const REPORT_SECTIONS = {
  summary: '一、报告概要',
  findings: '二、异常与发现',
  timeline: '三、会话时序',
  methodology: '四、证据口径与限制',
  issues: '会话异常',
  stats: 'TCP 分析标记统计',
} as const

/** 概要事实行(label/value 纯文本,渲染器自行按各自格式转义) */
export interface ReportFact {
  label: string
  value: string
}

/** 会话异常条目(来自 conv.issues;packetNumber 统一为 null 而非 undefined,便于渲染判空) */
export interface ReportIssueRow {
  type: string
  message: string
  packetNumber: number | null
}

/** TCP 分析标记统计:同一标记在会话内出现次数 + 首个样本包号 */
export interface ReportAnalysisStat {
  flag: string
  count: number
  firstPacket: number
}

/** 「二、异常与发现」内容:note 仅为「无任何异常与标记」时的明确文案,否则 null */
export interface ReportFindings {
  note: string | null
  issues: ReportIssueRow[]
  stats: ReportAnalysisStat[]
}

/** 「三、会话时序」内容 */
export interface ReportTimeline {
  /** 当前模式说明:完整逐行 / 紧凑区间 / 仅异常包(供各渲染器原样标注) */
  modeLabel: string
  /** transcriptTableLines 的原样 Markdown 输出(表头+分隔+数据行);无可列报文时为空数组 */
  tableLines: string[]
  /** 无表格时的空态文案;有表格时为 null */
  emptyText: string | null
}

/** 报告模型(承载全部章节内容;字段均为纯文本/数值,不含格式标记) */
export interface ReportModel {
  title: string
  generatedAt: string | null
  summary: ReportFact[]
  findings: ReportFindings
  timeline: ReportTimeline
  /** 「四、证据口径与限制」固定口径条目 */
  methodology: string[]
}

/** 固定口径:观察/推断分层、单观察点限制、正常参考不进入报告(措辞风格对齐对照页证据导出) */
const METHODOLOGY: readonly string[] = [
  '本报告区分「观察」与「推断」:观察为抓包中直接可见的现象(如 TCP 分析标记、字段取值),推断为基于现象的假设;两者均不构成对故障根因的断言。',
  '本次为单观察点抓包:只能看到经过抓包点的报文,无法定位丢包/延迟发生在哪个网络节点,也不能排除抓包点自身漏包(网卡 / ring buffer / 镜像口)。',
  'TCP 分析标记(重传 / 乱序 / 重复 ACK / 丢段等)是对「现象」的标注:重传不等于丢包,需结合序列空间缺口判断;无缺口的伪重传亦可能出现。',
  '「正常参考」示意仅用于解释正常行为应当如何,不进入本报告;报告只呈现实际观察到的会话内容,不做示意性补全。',
  '报告中时间为抓包相对时间(frame.time_relative,秒),长度为帧长(frame.len);采集被 snaplen 截断时,长度不代表原始帧大小。',
]

/** 与 exportTranscript.fmtBytes 同款人读字节数(该函数未导出,此处等价实现,改动需两处同步) */
function fmtBytes(b: number): string {
  return b >= 1024 ? (b / 1024).toFixed(1) + 'KB' : b + 'B'
}

/** 时序模式标注(供渲染器原样输出) */
function modeLabelOf(anomalies: boolean, compact: boolean): string {
  if (anomalies && compact) return '仅异常包 + 紧凑区间(只列带 ⚠ 分析标记的报文,连续相同报文合并为区间行)'
  if (anomalies) return '仅异常包(只列带 ⚠ 分析标记的报文,正常握手/ACK 已省略)'
  if (compact) return '紧凑区间(连续相同报文合并为区间行)'
  return '完整逐行(每包一行)'
}

/** 构建会话分析报告模型(纯函数、确定性:同输入同输出,无时间戳/随机数) */
export function buildReportModel(conv: Conversation, opts?: ReportOptions): ReportModel {
  const compact = opts?.compact === true
  const anomalies = opts?.anomalies === true

  const summary: ReportFact[] = [
    { label: '客户端', value: displayHost(conv.client) },
    { label: '服务端', value: displayHost(conv.server) },
    { label: '协议', value: conv.protocol },
    { label: '包数', value: String(conv.packetCount) },
    { label: '总字节', value: fmtBytes(conv.bytes) },
    { label: '时间范围', value: conv.start.toFixed(3) + '~' + conv.end.toFixed(3) + 's' },
    { label: '时间跨度', value: conv.duration.toFixed(3) + 's' },
  ]

  // 会话异常逐条入模;未关联包号统一为 null(渲染层据此省略,而非显示 undefined)
  const issues: ReportIssueRow[] = conv.issues.map((i) => ({
    type: i.type,
    message: i.message,
    packetNumber: i.packetNumber ?? null,
  }))

  // TCP 分析标记统计:按「标记首次出现」排序(Map 保持插入序),计数 + 首个样本包号
  const statMap = new Map<string, { count: number; firstPacket: number }>()
  for (const p of conv.packets) {
    for (const flag of p.tcpAnalysis ?? []) {
      const cur = statMap.get(flag)
      if (cur) cur.count++
      else statMap.set(flag, { count: 1, firstPacket: p.number })
    }
  }
  const stats: ReportAnalysisStat[] = [...statMap.entries()].map(([flag, s]) => ({
    flag,
    count: s.count,
    firstPacket: s.firstPacket,
  }))

  // 无任何异常条目与标记时,给「未检出异常」的明确文案(避免读者把空节当漏报)
  const note = issues.length === 0 && stats.length === 0 ? '未检出异常。' : null

  const tableLines = transcriptTableLines(conv, opts?.compact ?? null, anomalies ? 'anomalies' : 'full')
  const timeline: ReportTimeline = {
    modeLabel: modeLabelOf(anomalies, compact),
    tableLines,
    emptyText:
      tableLines.length === 0
        ? anomalies
          ? '该会话未检出 TCP 分析标记(重传/乱序/丢失/dup-ack 等),无异常报文可列'
          : '该会话无报文帧'
        : null,
  }

  return {
    title: '会话分析报告',
    generatedAt: opts?.generatedAt ?? null,
    summary,
    findings: { note, issues, stats },
    timeline,
    methodology: [...METHODOLOGY],
  }
}

/** 关联包号单元格:未关联包号时留空(而非显示 null/undefined);三个渲染器共用同一格式 */
export function packetCell(packetNumber: number | null): string {
  return packetNumber === null ? '' : '#' + packetNumber
}

/** 结构化表格(纯文本单元格),供 DOCX / HTML 渲染 */
export interface ReportTable {
  header: string[]
  rows: string[][]
}

/** 把 transcriptTableLines 产出的 Markdown 表格行解析为结构化行列(跳过分隔行)。
 *  mdCell 的转义在此做「展示层还原」:先还原 \| 与 \` 转义,再剥除代码标记反引号 ——
 *  Word/HTML 无代码语义,反引号若保留会原样出现在单元格里。
 *  已知投影损耗:原文自带反引号与代码标记在转义形式中不可区分,展示层统一剥除
 *  (仅影响 DOCX/HTML 展示;Markdown 侧承载原样转义行,无损)。 */
export function parseTranscriptTableLines(lines: string[]): ReportTable {
  let header: string[] = []
  const rows: string[][] = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('|')) continue
    const inner = trimmed.replace(/^\|/, '').replace(/\|$/, '')
    const cells = splitCells(inner).map(cellDisplay)
    if (cells.every((c) => /^:?-{2,}:?$/.test(c))) continue // 分隔行
    if (header.length === 0) {
      header = cells
      continue
    }
    rows.push(cells)
  }
  return { header, rows }
}

/** 按单元格切分:mdCell 已把数据内的竖线转义为 \|、反引号转义为 \`,切分时跳过转义对 */
function splitCells(inner: string): string[] {
  const out: string[] = []
  let cur = ''
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]
    if (ch === '\\' && (inner[i + 1] === '|' || inner[i + 1] === '`')) {
      cur += ch + inner[i + 1]
      i++
      continue
    }
    if (ch === '|') {
      out.push(cur)
      cur = ''
      continue
    }
    cur += ch
  }
  out.push(cur)
  return out
}

/** 单元格展示文本:还原转义(原文的竖线/反引号)后剥除代码标记反引号 */
function cellDisplay(s: string): string {
  return s.replace(/\\([|`])/g, '$1').replace(/`/g, '').trim()
}

/** 导出文件名:与 defaultCompareReportName / defaultEvidenceJsonName 同风格的 ASCII 安全名 */
export function defaultReportName(conv: Conversation, ext: 'md' | 'docx' | 'pdf'): string {
  const label = displayHost(conv.client) + ' ↔ ' + displayHost(conv.server)
  const safe = label.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60)
  return `report_${safe || 'session'}.${ext}`
}
