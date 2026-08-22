import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'

const DIR_CN: Record<string, string> = { request: '→ 请求', response: '← 响应', other: '↔ 其他' }

/** 时序叙述导出(Markdown):教学/周报可直接粘贴的文本版会话时间线 */
export function exportTranscript(conv: Conversation): string {
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
  lines.push('| # | 时间(s) | 方向 | 协议 | 概要 | 长度 |')
  lines.push('|---|---|---|---|---|---|')
  for (const p of conv.packets) {
    const flags = p.tcpAnalysis?.length ? ' ⚠[' + p.tcpAnalysis.join(',') + ']' : ''
    lines.push('| ' + p.number + ' | ' + p.time.toFixed(3) + ' | ' + (DIR_CN[p.direction] ?? p.direction) + ' | ' + p.proto + ' | ' + (p.info ?? '') + flags + ' | ' + p.len + 'B |')
  }
  lines.push('')
  lines.push('_由 pUI 导出_')
  return lines.join('\n')
}

function fmtBytes(b: number): string {
  return b >= 1024 ? (b / 1024).toFixed(1) + 'KB' : b + 'B'
}