import type { Conversation, Packet } from '../model/types'
import { displayHost } from '../model/types'
import { analyzeConversationIssues, type IssueOptions } from './issues'

export function flowKey(p: Packet): string {
  let a: string
  let b: string
  if (p.transport === 'tcp' || p.transport === 'udp') {
    if (p.srcPort != null && p.dstPort != null) {
      a = p.srcIp ? `${p.srcIp}:${p.srcPort}` : (p.srcMac ?? '?')
      b = p.dstIp ? `${p.dstIp}:${p.dstPort}` : (p.dstMac ?? '?')
    } else {
      // 任一侧端口缺失(畸形/截断帧等):端口化端点会因方向不同而换边,
      // 双侧统一退化为地址级 key,保证同流双向 key 一致(否则会话被拆成两个单向)
      a = p.srcIp ?? p.srcMac ?? '?'
      b = p.dstIp ?? p.dstMac ?? '?'
    }
  } else {
    a = p.srcIp ?? p.srcMac ?? '?'
    b = p.dstIp ?? p.dstMac ?? '?'
  }
  const [lo, hi] = a <= b ? [a, b] : [b, a]
  // tcp.stream 是连接身份的权威来源:同一端点对复用端口或并发连接时(实测 tshark 给出
  // stream=0/1),仅按端点对归并会把多条连接混成一个会话,其握手、序列号与异常统计
  // 全部串味,TCP 状态机在这种会话上运行没有意义。缺该字段(旧抓包/非 TCP)时才退回端点对。
  const stream = p.tcpStream != null ? `|s${p.tcpStream}` : ''
  return `${p.transport}|${lo}|${hi}${stream}`
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

export function aggregateConversations(packets: Packet[], opts?: IssueOptions): Conversation[] {
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
      return { ...built, issues: analyzeConversationIssues(built, opts) }
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
