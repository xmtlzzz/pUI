export type Direction = 'request' | 'response' | 'other'
export type Transport = 'tcp' | 'udp' | 'icmp' | 'arp' | 'other'

export interface Packet {
  number: number
  time: number // frame.time_relative 秒
  timeEpoch?: number // frame.time_epoch(绝对时间,秒),供相对/绝对时间戳切换
  interfaceId?: string // frame.interface_id(捕获接口索引),供接口数统计
  len: number // frame.len 字节
  /** frame.cap_len(实际捕获字节)。< len 即被 snaplen 截断,属采集完整性信号而非网络丢包证据 */
  capLen?: number
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
  /** tcp.stream:tshark 的流 id。同一端点对复用端口/并发连接时,只有它能区分不同连接;
   *  缺失(旧抓包/非 TCP)时为 undefined —— 不可用 0 代替,0 是合法流 id */
  tcpStream?: number
  /** tcp.window_size:接收窗口通告字节数(M5 窗口事件用)。undefined = 字段缺失,
   *  不做推测;0 = 零窗口(接收缓冲区满),语义完全不同 */
  tcpWindow?: number
  /** tcp.len:TCP 载荷字节数。序列号推进必须用它,frame.len 含各层头部不可用于序列空间。
   *  0 表示纯 ACK/keep-alive(与 undefined "字段缺失"语义不同) */
  tcpLen?: number
  /** tcp.completeness 位掩码:SYN=1 SYN-ACK=2 ACK=4 DATA=8 FIN=16 RST=32。
   *  (值 & 0x03) === 0 即中途抓包,此时"流起始丢段/未正常关闭"结论不可信 */
  tcpCompleteness?: number
  /** SACK 块 [左边界, 右边界)。平铺 -e 模式下 tshark 以并行数组给出多块,逐对 zip 得到;
   *  协议树形态只保留最后一块(tshark 限制),故块数可能少于实际 —— 由分析层降级为限制而非事实 */
  tcpSackBlocks?: Array<[number, number]>
  /** tcp.analysis.duplicate_ack_num:这是第几个重复 ACK(tshark 自己的计数) */
  tcpDupAckNum?: number
  /** tshark TCP 分析标签:retransmission / fast-retransmission / duplicate-ack / lost-segment /
   *  out-of-order / spurious-retransmission。仅为「观察到的现象」,不等于结论 */
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
  /** 按异常类型细化筛选(可选:空数组 = 不限类型) */
  issueTypes?: string[]
}

export function emptyFilter(): FilterCondition {
  return { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false, issueTypes: [] }
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
  /** tshatk JSON → 会话聚合的解析耗时(毫秒),由顶层计时注入;旧数据缺失时可选 */
  parseMs?: number
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

/** 展示用主机名:裸 IPv6 整体保留;其余(IPv4:port / IPv6:port / MAC)剥离端口。
 *  已知局限:带端口 IPv6("2001:db8::1:443")与尾段数字型裸地址("fe80::1:10")无法仅凭字符串区分,
 *  故按"含 :: 且各组合法"判为裸 IPv6 整体保留——端口会混进展示(仅影响展示,方向判定双侧同串不受影响)。 */
export function displayHost(s: string): string {
  return isBareIpv6(s) ? s : hostOf(s)
}
