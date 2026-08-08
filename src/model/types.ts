export type Direction = 'request' | 'response' | 'other'
export type Transport = 'tcp' | 'udp' | 'icmp' | 'arp' | 'other'

export interface Packet {
  number: number
  time: number // frame.time_relative 秒
  len: number // frame.len 字节
  transport: Transport
  proto: string // 应用层协议:http / dns / tls / tcp / udp / icmp / arp ...
  srcIp?: string
  dstIp?: string
  srcMac?: string
  dstMac?: string
  srcPort?: number
  dstPort?: number
  tcpFlags?: string // "0x0012"
  tcpSeq?: number
  tcpAck?: number
  /** tshark TCP 分析标签:retransmission / fast-retransmission / out-of-order / duplicate-ack / lost-segment */
  tcpAnalysis?: string[]
  httpTime?: number // http.time:请求到响应延迟(秒)
  httpMethod?: string
  httpUri?: string
  httpCode?: string
  dnsQuery?: string
  tlsType?: string
  info?: string // 概要,如 "HTTP GET /"、"TCP SYN-ACK"
  direction: Direction
}

export interface Conversation {
  id: string
  client: string // "ip:port" 或 "ip" 或 "mac"
  server: string
  protocol: string // 会话主协议
  packetCount: number
  bytes: number
  start: number
  end: number
  duration: number
  packets: Packet[] // 按 time 升序
  issues: ConversationIssue[]
}

/** 会话级可疑丢包/异常标注 */
export interface ConversationIssue {
  type: 'syn-no-reply' | 'unanswered' | 'one-way' | 'no-close' | 'retransmission' | 'slow-response' | 'rst' | 'lost-segment' | 'out-of-order' | 'dup-ack'
  message: string
  packetNumber?: number
}

export interface FilterCondition {
  protocol: string[]
  srcIp: string[]
  dstIp: string[]
  srcPort: number[]
  dstPort: number[]
  negate: boolean
  issueOnly: boolean
}

export function emptyFilter(): FilterCondition {
  return { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false }
}

export interface FilterOptions {
  protocols: string[]
  srcIps: string[]
  dstIps: string[]
  ports: number[]
}

export interface CaptureMeta {
  fileName: string
  packetCount: number
  interfaces: number
  timeStart: number
  timeEnd: number
  fileSize: number
}

/**
 * 从 "host:port" 中分离主机与端口,兼容 IPv4/IPv6/MAC:
 * - "192.168.1.10:80"  → host "192.168.1.10", port "80"
 * - "2001:db8::1:443"  → host "2001:db8::1", port "443"(取最后一个冒号)
 * - "aa:bb:cc:dd:ee:ff"(MAC,无端口)→ host 整个字符串
 * - "8.8.8.8"(无端口)→ host 整个字符串
 */
export function hostPort(s: string): { host: string; port?: string } {
  const i = s.lastIndexOf(':')
  if (i <= 0) return { host: s } // 无冒号或冒号在开头 → 整个即主机
  const tail = s.slice(i + 1)
  const rest = s.slice(0, i)
  // MAC(6 组两位十六进制)整体视为主机,不拆分尾部
  const isMac = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(s)
  if (!isMac && /^\d+$/.test(tail)) {
    const colonCount = (s.match(/:/g) ?? []).length
    // 单冒号 → IPv4:port;多冒号且尾段 2-5 位 → IPv6:port
    const isPort = colonCount === 1 || (tail.length >= 2 && tail.length <= 5)
    if (isPort) return { host: rest, port: tail }
  }
  return { host: s }
}

export function hostOf(s: string): string {
  return hostPort(s).host
}

/**
 * 是否为(无端口的)裸 IPv6 地址:含 ≥2 个冒号、至少一段空段(::)、各段为 1-4 位十六进制。
 * "fe80::1:10" 这类以数字结尾的裸地址,hostPort 的启发式会误当作 host:port,
 * 这里整体保留,避免方向比较/端点标签被截断。
 */
export function isBareIpv6(s: string): boolean {
  if (!s.includes(':')) return false
  const groups = s.split(':')
  if (groups.length < 3) return false
  let empty = 0
  for (const g of groups) {
    if (g === '') {
      empty++
      continue
    }
    if (g.length > 4 || !/^[0-9a-fA-F]+$/.test(g)) return false
  }
  return empty >= 1
}

/** 展示用主机名:裸 IPv6 整体保留;其余(IPv4:port / IPv6:port / MAC)剥离端口 */
export function displayHost(s: string): string {
  return isBareIpv6(s) ? s : hostOf(s)
}
