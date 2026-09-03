import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'

const DIR_CN: Record<string, string> = { request: '→ 请求', response: '← 响应', other: '↔ 其他' }

/**
 * Markdown 表格单元格转义:报文字段(info/URI/DNS 查询名)是抓包文件里的不可信内容,
 * 裸拼会破坏表格(| 与换行)或在下游 Markdown 渲染器注入 HTML/图片标签。
 * 反引号包裹为代码形式并转义内部反引号,尖括号剥除防 <img onerror> 透传,
 * & 实体转义(先于其它替换,否则 &amp;/&lt; 等字面量会被渲染器二次解码产生歧义)。
 * 转义串用 BS+BT 显式构造:字符串字面量 '\\`' 实际只是单个反引号(静默失效的转义)。
 */
const MD_BS = String.fromCharCode(92) // 反斜杠
const MD_BT = String.fromCharCode(96) // 反引号

export function mdCell(s: string): string {
  const noAngle = s.replace(/&/g, '&amp;').replace(/[<>]/g, '')
  return (
    MD_BT +
    noAngle.split(MD_BT).join(MD_BS + MD_BT).split('|').join(MD_BS + '|').replace(/\r?\n/g, ' ') +
    MD_BT
  )
}

/** 行内文本(Markdown 叙述行的非表格部分):剥尖括号(防 HTML 注入)、拍平换行。
 *  与 renderReportMd.mdText / compare.render.mdText 同口径 —— 不包裹反引号。 */
function mdText(s: string): string {
  return s.replace(/[<>]/g, '').replace(/\r?\n/g, ' ')
}

/** 反引号代码包裹的行内值(客户端/服务端端点等):先转义 & 再剥尖括号,
 *  内部反引号转义防逃逸出代码跨距(早闭后 <img onerror> 落入普通文本被渲染)。 */
function mdInline(s: string): string {
  const noAngle = s.replace(/&/g, '&amp;').replace(/[<>]/g, '')
  return MD_BT + noAngle.split(MD_BT).join(MD_BS + MD_BT) + MD_BT
}

/** 时序表格行(仅表格:表头 + 分隔行 + 数据行,Markdown 转义由 mdCell 完成)。
 *  抽为独立导出的原因:会话分析报告(src/export/report)的三、会话时序章节与叙述导出
 *  必须同源同口径 —— 紧凑/仅异常的合并与过滤逻辑只此一份,避免两处实现漂移。
 *  compact=true:把「方向+协议+概要+分析标记」连续相同的报文合并为区间行;
 *  mode='anomalies':只保留带 ⚠ 分析标记的报文(丢弃纯正常握手/ACK)。
 *  无可列报文(会话无帧 / 仅异常模式下无标记)时返回空数组,空态文案由调用方各自措辞。 */
export function transcriptTableLines(
  conv: Conversation,
  compact: boolean | null = null,
  mode: 'full' | 'anomalies' = 'full',
): string[] {
  const anomalyOnly = mode === 'anomalies'
  // 待导出报文:仅异常模式过滤出带分析标记的;否则全量(紧凑则进一步合并)
  const packets = anomalyOnly ? conv.packets.filter((p) => p.tcpAnalysis?.length) : conv.packets
  if (packets.length === 0) return []
  const lines: string[] = []
  if (!compact) {
    lines.push('| # | 时间(s) | 方向 | 协议 | 概要 | 长度 |')
    lines.push('|---|---|---|---|---|---|')
    for (const p of packets) {
      lines.push(transcriptRow(p))
    }
  } else {
    lines.push('| 报文区间 | 包数 | 方向 | 协议 | 概要 | 长度 |')
    lines.push('|---|---|---|---|---|---|')
    for (const g of groupConsecutive(packets)) {
      lines.push(compactRow(g))
    }
  }
  return lines
}

/** 时序叙述导出(Markdown):教学/周报可直接粘贴的文本版会话时间线。
 *  compact=true:把「方向+协议+概要+分析标记」连续相同的报文合并为一行区间
 *  `#X–#Y · N 包 · ...`,大幅减少重复 ACK/PSH 行数,避免巨大会话在 docx/typora 打开卡顿。
 *  mode='anomalies'(周报):只保留带 ⚠ 分析标记(重传/乱序/丢失/dup-ack 等)的报文,
 *  丢掉纯正常握手/ACK;仅异常模式恒走紧凑合并(异常包足够少,合并更易读)。
 *  默认 full 逐行完整导出(旧行为);null/undefined 兼容。 */
export function exportTranscript(
  conv: Conversation,
  compact: boolean | null = null,
  mode: 'full' | 'anomalies' = 'full',
): string {
  const lines: string[] = []
  lines.push('# 会话时序叙述')
  lines.push('')
  // 头部行也是不可信抓包内容(端点串/协议名可含 HTML 标签),与 mdCell 同口径:
  // 反引号包裹 + 内部反引号转义 + 剥尖括号(防 <img onerror> 透传给下游 Markdown 渲染器)
  lines.push('- 客户端: ' + mdInline(displayHost(conv.client)))
  lines.push('- 服务端: ' + mdInline(displayHost(conv.server)))
  lines.push('- 协议: ' + mdText(conv.protocol) + ' · ' + conv.packetCount + ' 包 · ' + fmtBytes(conv.bytes) + ' · ' + conv.start.toFixed(3) + '~' + conv.end.toFixed(3) + 's')
  const anomalyOnly = mode === 'anomalies'
  if (anomalyOnly) lines.push('- 模式: 仅异常包(只列带 ⚠ 分析标记的报文,正常握手/ACK 已省略)')
  if (conv.issues.length) {
    lines.push('- ⚠ 异常: ' + conv.issues.map((i) => mdText(i.message)).join('; '))
  }
  lines.push('')

  // 表格行复用 transcriptTableLines(与会话分析报告同源);空态文案保留本导出的既有措辞
  const table = transcriptTableLines(conv, compact, mode)
  if (table.length === 0) {
    lines.push(anomalyOnly
      ? '_该会话未检出 TCP 分析标记(重传/乱序/丢失/dup-ack 等),无异常报文可列_'
      : '_该会话无报文帧_')
    lines.push('')
    lines.push('_由 pUI 导出_')
    return lines.join('\n')
  }
  lines.push(...table)
  lines.push('')
  lines.push('_由 pUI 导出_')
  return lines.join('\n')
}

/** 逐行导出的单包表格行 */
function transcriptRow(p: PacketLike): string {
  const flags = p.tcpAnalysis?.length ? ' ⚠[' + mdCell(p.tcpAnalysis.join(',')) + ']' : ''
  return '| ' + p.number + ' | ' + p.time.toFixed(3) + ' | ' + (DIR_CN[p.direction] ?? p.direction) + ' | ' + mdCell(p.proto) + ' | ' + (p.info ? mdCell(p.info) : '') + flags + ' | ' + p.len + 'B |'
}

interface PacketLike {
  number: number
  time: number
  direction: string
  proto: string
  info?: string
  len: number
  tcpAnalysis?: string[]
}

/** 连续相同行的分组:键 = 方向+协议+概要+分析标记(忽略长度与时间——长度并入表,时间取区间首尾) */
interface CompactGroup {
  _key: string
  start: number
  end: number
  count: number
  dir: string
  proto: string
  info?: string
  analysis?: string[]
  len: number
  timeStart: number
  timeEnd: number
}

function groupConsecutive(packets: PacketLike[]): CompactGroup[] {
  const out: CompactGroup[] = []
  let cur: CompactGroup | null = null
  for (const p of packets) {
    const key = p.direction + '|' + p.proto + '|' + (p.info ?? '') + '|' + (p.tcpAnalysis?.join(',') ?? '')
    if (cur && key === cur._key) {
      cur.end = p.number
      cur.count++
      cur.timeEnd = p.time
      cur.len = p.len // 同组内长度通常一致;不一致时保留最后一行长度(区间代表性)
      continue
    }
    if (cur) out.push(cur)
    cur = {
      _key: key,
      start: p.number,
      end: p.number,
      count: 1,
      dir: p.direction,
      proto: p.proto,
      info: p.info,
      analysis: p.tcpAnalysis ? [...p.tcpAnalysis] : undefined,
      len: p.len,
      timeStart: p.time,
      timeEnd: p.time,
    }
  }
  if (cur) out.push(cur)
  return out
}

/** 区间行:连续相同报文合并为一行,时间区间标注首末;单包退化为普通行形态 */
function compactRow(g: CompactGroup): string {
  const flags = g.analysis?.length ? ' ⚠[' + mdCell(g.analysis.join(',')) + ']' : ''
  const range = g.count === 1 ? '#' + g.start : '#' + g.start + '\u2013#' + g.end
  const time = g.count === 1 ? g.timeStart.toFixed(3) : g.timeStart.toFixed(3) + '~' + g.timeEnd.toFixed(3)
  void time
  return '| ' + range + ' | ' + g.count + ' | ' + (DIR_CN[g.dir] ?? g.dir) + ' | ' + mdCell(g.proto) + ' | ' + (g.info ? mdCell(g.info) : '') + flags + ' | ' + g.len + 'B |'
}

function fmtBytes(b: number): string {
  return b >= 1024 ? (b / 1024).toFixed(1) + 'KB' : b + 'B'
}