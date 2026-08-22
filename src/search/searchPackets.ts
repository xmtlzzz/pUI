import type { Conversation, Packet } from '../model/types'

export interface ConvMatch {
  convId: string
  numbers: number[]
}

/** 报文全文搜索:协议/IP/端口/MAC/info/URI/DNS/TCP标志子串匹配(大小写不敏感)。
 *  返回命中的会话与报文号,供会话列表过滤与时序图高亮定位。 */
export function searchConversations(convs: Conversation[], rawQuery: string): ConvMatch[] {
  const q = rawQuery.trim().toLowerCase()
  if (!q) return []
  const out: ConvMatch[] = []
  for (const c of convs) {
    const numbers: number[] = []
    for (const p of c.packets) {
      if (packetMatches(p, q)) numbers.push(p.number)
    }
    if (numbers.length) out.push({ convId: c.id, numbers })
  }
  return out
}

function packetMatches(p: Packet, q: string): boolean {
  return (
    p.proto.toLowerCase().includes(q) ||
    (p.info?.toLowerCase().includes(q) ?? false) ||
    (p.srcIp?.toLowerCase().includes(q) ?? false) ||
    (p.dstIp?.toLowerCase().includes(q) ?? false) ||
    (p.srcMac?.toLowerCase().includes(q) ?? false) ||
    (p.dstMac?.toLowerCase().includes(q) ?? false) ||
    (p.srcPort != null && String(p.srcPort).includes(q)) ||
    (p.dstPort != null && String(p.dstPort).includes(q)) ||
    (p.httpUri?.toLowerCase().includes(q) ?? false) ||
    (p.dnsQuery?.toLowerCase().includes(q) ?? false) ||
    (p.httpCode?.toLowerCase().includes(q) ?? false) ||
    (p.tcpFlags?.toLowerCase().includes(q) ?? false)
  )
}
