import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'

export interface SummaryStats {
  conversationCount: number
  packetCount: number
  totalBytes: number
  duration: number
  issueConversations: number
  protocolCounts: Array<{ protocol: string; count: number }>
  issueTypeCounts: Array<{ type: string; count: number }>
  topHosts: Array<{ host: string; bytes: number }>
}

/** 分析摘要:协议分布 / 异常分布 / Top 主机,全部由现有 conversations 派生(安全初看场景) */
export function deriveSummary(convs: Conversation[]): SummaryStats {
  const protos = new Map<string, number>()
  const issues = new Map<string, number>()
  const hosts = new Map<string, number>()
  let packetCount = 0
  let totalBytes = 0
  let issueConvs = 0
  let start = Number.POSITIVE_INFINITY
  let end = Number.NEGATIVE_INFINITY
  for (const c of convs) {
    packetCount += c.packetCount
    totalBytes += c.bytes
    if (c.start < start) start = c.start
    if (c.end > end) end = c.end
    if (c.issues.length) issueConvs++
    protos.set(c.protocol, (protos.get(c.protocol) ?? 0) + 1)
    for (const i of c.issues) issues.set(i.type, (issues.get(i.type) ?? 0) + 1)
    // 与 hostStats 同守卫:'?'(无 srcIp/dstIp 报文的 flowKey 退化值)与空串不进 topHosts
    const ch = displayHost(c.client)
    const sh = displayHost(c.server)
    if (ch && ch !== '?') hosts.set(ch, (hosts.get(ch) ?? 0) + c.bytes)
    if (sh && sh !== '?') hosts.set(sh, (hosts.get(sh) ?? 0) + c.bytes)
  }
  const byDesc = <T,>(m: Map<string, T>) => [...m.entries()].sort((a, b) => (b[1] as number) - (a[1] as number))
  return {
    conversationCount: convs.length,
    packetCount,
    totalBytes,
    duration: convs.length ? end - start : 0,
    issueConversations: issueConvs,
    protocolCounts: byDesc(protos).slice(0, 10).map(([protocol, count]) => ({ protocol, count })),
    issueTypeCounts: byDesc(issues).map(([type, count]) => ({ type, count })),
    topHosts: byDesc(hosts).slice(0, 5).map(([host, bytes]) => ({ host, bytes })),
  }
}
