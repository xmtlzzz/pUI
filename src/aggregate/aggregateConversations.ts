import type { Conversation, Packet } from '../model/types'

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
      conv = { id: key, client: '', server: '', protocol: '', packetCount: 0, bytes: 0, start: p.time, end: p.time, duration: 0, packets: [] }
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
        const syn = packets.find((p) => p.tcpFlags && (Number.parseInt(p.tcpFlags, 16) & 0x02))
        if (syn && syn.srcIp) {
          client = sideOf(syn, true)
          server = sideOf(syn, false)
        }
      }
      if (!client && (transport === 'tcp' || transport === 'udp')) {
        // 无 SYN:取端口较大者(临时端口)为客户端,退化用首包方向
        const first = packets[0]
        const a = sideOf(first, true)
        const b = sideOf(first, false)
        const pa = first.srcPort ?? 0
        const pb = first.dstPort ?? 0
        if (pa !== pb) {
          client = pa > pb ? a : b
          server = pa > pb ? b : a
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
      return {
        ...conv,
        client,
        server,
        protocol: bestProto(protos),
        packetCount: packets.length,
        start: packets[0].time,
        end: packets[packets.length - 1].time,
        duration: packets[packets.length - 1].time - packets[0].time,
        packets,
      }
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
  return s.split(':')[0] // 仅比较 IP/MAC 前缀,端口不影响方向归属
}
