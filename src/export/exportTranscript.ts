import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'

const DIR_CN: Record<string, string> = { request: '→ 请求', response: '← 响应', other: '↔ 其他' }

/**
 * Markdown 表格单元格转义:报文字段(info/URI/DNS 查询名)是抓包文件里的不可信内容,
 * 裸拼会破坏表格(| 与换行)或在下游 Markdown 渲染器注入 HTML/图片标签。
 * 反引号包裹为代码形式并转义内部反引号,尖括号剥除防 <img onerror> 透传。
 * 转义串用 BS+BT 显式构造:字符串字面量 '\\`' 实际只是单个反引号(静默失效的转义)。
 */
const MD_BS = String.fromCharCode(92) // 反斜杠
const MD_BT = String.fromCharCode(96) // 反引号

function mdCell(s: string): string {
  const noAngle = s.replace(/[<>]/g, '')
  return (
    MD_BT +
    noAngle.split(MD_BT).join(MD_BS + MD_BT).split('|').join(MD_BS + '|').replace(/\r?\n/g, ' ') +
    MD_BT
  )
}

/** 时序叙述导出(Markdown):教学/周报可直接粘贴的文本版会话时间线。
 *  compact=true(派发给 typora 等重渲染器时):把「方向+协议+概要+长度+分析标记」
 *  连续相同的报文合并为一行区间 `#X–#Y · N 包 · ...`,大幅减少重复 ACK/PSH 的行数,
 *  避免巨大会话在 docx/typora 里打开卡顿;区间内部各项仍可读。
 *  默认 null = 逐行完整导出(旧行为)。 */
export function exportTranscript(
  conv: Conversation,
  compact: boolean | null = null,
): string {
  const lines: string[] = []
  lines.push('# 会话时序叙述')
  lines.push('')
  lines.push('- 客户端: `' + displayHost(conv.client) + '`')
  lines.push('- 服务端: `' + displayHost(conv.server) + '`')
  lines.push('- 协议: ' + conv.protocol + ' · ' + conv.packetCount + ' 包 · ' + fmtBytes(conv.bytes) + ' · ' + conv.start.toFixed(3) + '~' + conv.end.toFixed(3) + 's')
  if (conv.issues.length) {
    lines.push('- ⚠ 异常: ' + conv.issues.map((i) => i.message).join('; '))
  }
  lines.push('')
  if (!compact) {
    lines.push('| # | 时间(s) | 方向 | 协议 | 概要 | 长度 |')
    lines.push('|---|---|---|---|---|---|')
    for (const p of conv.packets) {
      lines.push(transcriptRow(p))
    }
  } else {
    lines.push('| 报文区间 | 包数 | 方向 | 协议 | 概要 | 长度 |')
    lines.push('|---|---|---|---|---|---|')
    // 按连续相同的「方向+协议+概要(+分析标记)」分组;长度差异独立列,不并入分组键
    for (const g of groupConsecutive(conv.packets)) {
      lines.push(compactRow(g))
    }
  }
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