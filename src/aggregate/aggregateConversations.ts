import type { Conversation, Packet } from '../model/types'
import { displayHost } from '../model/types'
import { analyzeConversationIssues } from './issues'

function side(p: Packet): string {
  if (p.transport === 'tcp' || p.transport === 'udp') {
    if (p.srcIp && p.srcPort != null && p.dstIp && p.dstPort != null) return `${p.srcIp}:${p.srcPort}`
  }
  if (p.srcIp) return p.srcIp
  if (p.srcMac) return p.srcMac
  return '?'
}

export function flowKey(p: Packet): string {
  const a = side(p)
  const b =
    p.transport === 'tcp' || p.transport === 'udp'
      ? p.dstIp && p.dstPort != null
        ? `${p.dstIp}:${p.dstPort}`
        : (p.dstIp ?? p.dstMac ?? '?')
      : (p.dstIp ?? p.dstMac ?? '?')
  const [lo, hi] = a <= b ? [a, b] : [b, a]
  return `${p.transport}|${lo}|${hi}`
}

const PROTO_RANK: Record<string, number> = {
  http: 5, https: 5, tls: 5, quic: 5,
  dns: 4, mdns: 4,
  icmp: 3, arp: 3,
  tcp: 2, udp: 2,
}

function bestProto(protos: Set<string>): string {
  let best = 'unknown'
  let bestRank = -1
  for (const p of protos) {
    const r = PROTO_RANK[p] ?? 0
    if (r > bestRank) {
      best = p
      bestRank = r
    }
  }
  return best
}

export function aggregateConversations(packets: Packet[]): Conversation[] {
  const map = new Map<string, Conversation>()
  for (const p of packets) {
    const key = flowKey(p)
    let conv = map.get(key)
    if (!conv) {
      conv = { id: key, client: '', server: '', protocol: '', packetCount: 0, bytes: 0, start: p.time, end: p.time, duration: 0, packets: [], issues: [] }
      map.set(key, conv)
    }
    conv.packets.push(p)
    conv.bytes += p.len
    if (p.time < conv.start) conv.start = p.time
    if (p.time > conv.end) conv.end = p.time
  }

  return [...map.values()]
    .map((conv) => {
      const packets = [...conv.packets].sort((a, b) => a.time - b.time)
      const transport = packets[0].transport
      let client: string | null = null
      let server: string | null = null

      if (transport === 'tcp') {
        // 找"纯 SYN"(含 SYN 位、无 ACK 位);SYN-ACK(0x0012)含 SYN 位但不能当连接发起方,
        // 否则从半握手中间开始抓包时会把 client/server 反转
        const syn = packets.find(
          (p) =>
            p.tcpFlags &&
            (Number.parseInt(p.tcpFlags, 16) & 0x02) !== 0 &&
            (Number.parseInt(p.tcpFlags, 16) & 0x10) === 0,
        )
        if (syn && syn.srcIp) {
          client = sideOf(syn, true)
          server = sideOf(syn, false)
        }
      }
      if (!client && (transport === 'tcp' || transport === 'udp')) {
        // 无 SYN:通常"知名端口(<1024)=服务端、临时端口=客户端";
        // 两侧同为知名或同为临时端口时,取首包发起方为客户端(退化)
        const first = packets[0]
        const a = sideOf(first, true)
        const b = sideOf(first, false)
        const pa = first.srcPort ?? 0
        const pb = first.dstPort ?? 0
        const aWellKnown = pa > 0 && pa < 1024
        const bWellKnown = pb > 0 && pb < 1024
        if (aWellKnown !== bWellKnown) {
          client = aWellKnown ? b : a
          server = aWellKnown ? a : b
        } else {
          client = a
          server = b
        }
      }
      if (!client) {
        const first = packets[0]
        client = first.srcIp ?? first.srcMac ?? '?'
        server = first.dstIp ?? first.dstMac ?? '?'
      }
      if (server == null) server = '?'

      const clientSide = sideKey(client)
      for (const p of packets) {
        p.direction = sideKey(sideOf(p, true)) === clientSide ? 'request' : 'response'
      }

      const protos = new Set(packets.map((p) => p.proto))
      const built = {
        ...conv,
        client,
        server,
        protocol: bestProto(protos),
        packetCount: packets.length,
        start: packets[0].time,
        end: packets[packets.length - 1].time,
        duration: packets[packets.length - 1].time - packets[0].time,
        packets,
        issues: [] as Conversation['issues'],
      }
      return { ...built, issues: analyzeConversationIssues(built) }
    })
    .sort((a, b) => a.start - b.start)
}

function sideOf(p: Packet, src: boolean): string {
  if (p.transport === 'tcp' || p.transport === 'udp') {
    if (src) return p.srcIp && p.srcPort != null ? `${p.srcIp}:${p.srcPort}` : (p.srcIp ?? p.srcMac ?? '?')
    return p.dstIp && p.dstPort != null ? `${p.dstIp}:${p.dstPort}` : (p.dstIp ?? p.dstMac ?? '?')
  }
  return src ? (p.srcIp ?? p.srcMac ?? '?') : (p.dstIp ?? p.dstMac ?? '?')
}

function sideKey(s: string): string {
  return displayHost(s) // 兼容 IPv4/IPv6/MAC;裸 IPv6 不截断,host:port 才剥离端口
}
