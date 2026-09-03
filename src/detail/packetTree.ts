import type { Packet } from '../model/types'
import { tcpInfo } from '../parse/parsePackets'

export interface ByteRange {
  /** 起始字节偏移(含) */
  start: number
  /** 结束字节偏移(不含) */
  end: number
}

export interface DetailNode {
  key: string
  label: string // 行文本
  value?: string
  children?: DetailNode[]
  /** 该节点对应的报文内字节区域(协议层估算;hex 联动定位用)。
   *  仅「区域型」节点(层标题)携带;叶子字段节点不携带(见 detailRegion) */
  range?: ByteRange
}

/**
 * 协议层 → 报文内字节区域的估算(数据层限制的降级方案)。
 *
 * 抓包 JSON 是 tshark -e 平铺精选字段(见 src-tauri CAPTURE_FIELDS),不含
 * 帧内字段的字节偏移(_raw/offset 字段),因此无法给出「字段级」精确字节范围。
 * 这里的估算基于标准头部尺寸 + 已知载荷长度,给出「协议层级」区域:
 *  - 帧:整包 [0, frame.cap_len)(截断帧取实际捕获字节数);
 *  - L2 以太网:固定 14 字节;
 *  - L3:IPv4 20 字节 / IPv6 40 字节(不含 IP 选项);
 *  - L4:TCP 20 字节 / UDP 8 字节(不含 TCP 选项);
 *  - 应用层:优先用 tcp.len(精确载荷字节数)从帧尾反推(数据层唯一精确的载荷量),
 *    否则用「L4 头之后」估算;数据层拿不到任何偏移时退化为整帧区域。
 * 区域是估算而非事实:IP/TCP 选项、IPv6 扩展头、vlan 标签等会引入偏差,
 * 故作为「粗粒度联动」展示,不冒充字段级定位。
 */
function headerSize(p: Packet): { l3: number; l4: number } {
  if (p.transport === 'arp') return { l3: 0, l4: 0 }
  const isV6 = p.srcIp?.includes(':') || p.dstIp?.includes(':')
  const l3 = isV6 ? 40 : 20
  const l4 = p.transport === 'udp' ? 8 : p.transport === 'tcp' ? 20 : 0
  return { l3, l4 }
}

/** 由链路区段链计算各层标题节点的字节区域(纯函数,见 detailRegion) */
export function detailRanges(p: Packet): Partial<Record<string, ByteRange>> {
  const cap = p.capLen ?? p.len
  if (cap <= 0) return {}
  const { l3, l4 } = headerSize(p)
  const eth = p.srcMac || p.dstMac ? 14 : 0
  const l3Start = eth
  const l4Start = l3Start + l3
  const appStart = l4Start + l4
  const ranges: Partial<Record<string, ByteRange>> = { frame: { start: 0, end: cap } }
  if (eth) ranges.l2 = { start: 0, end: eth }
  if (l3) ranges.l3 = { start: l3Start, end: l4Start }
  if (p.transport === 'tcp' || p.transport === 'udp') {
    ranges[p.transport] = { start: l4Start, end: appStart }
    // 应用层:优先 tcp.len(精确载荷字节数,数据层唯一可靠量)从帧尾反推;
    // 否则取「L4 头之后」的估算区域(可能空,此时回退整帧)
    if (p.tcpLen != null && p.tcpLen > 0 && p.tcpLen <= cap) {
      ranges.app = { start: cap - p.tcpLen, end: cap }
    } else if (appStart < cap) {
      ranges.app = { start: appStart, end: cap }
    }
  } else if (p.transport === 'arp') {
    ranges.arp = { start: eth, end: cap }
  }
  return ranges
}

/** 报文详情分层树(帧 → L2 → L3 → L4 → 应用层):按层级组织字段,可折叠展示 */
export function buildPacketTree(p: Packet): DetailNode[] {
  const ranges = detailRanges(p)
  const nodes: DetailNode[] = []
  nodes.push({ key: 'frame', label: '帧 Frame', range: ranges.frame, children: [
    { key: 'no', label: '编号', value: String(p.number) },
    { key: 'time', label: '相对时间', value: p.time.toFixed(3) + 's' },
    { key: 'timeAbs', label: '绝对时间', value: p.timeEpoch != null ? new Date(p.timeEpoch * 1000).toLocaleString() : '—' },
    { key: 'len', label: '长度', value: p.len + 'B' },
    { key: 'iface', label: '接口', value: p.interfaceId != null ? '#' + p.interfaceId : '—' },
    { key: 'dir', label: '方向', value: p.direction === 'request' ? '请求' : p.direction === 'response' ? '响应' : '其他' },
  ] })
  if (p.srcMac || p.dstMac) {
    nodes.push({ key: 'l2', label: '以太网 L2', range: ranges.l2, children: [
      { key: 'src', label: '源 MAC', value: p.srcMac ?? '—' },
      { key: 'dst', label: '目的 MAC', value: p.dstMac ?? '—' },
    ] })
  }
  if (p.srcIp || p.dstIp) {
    const isV6 = (p.srcIp?.includes(':') ?? false) || (p.dstIp?.includes(':') ?? false)
    nodes.push({ key: 'l3', label: isV6 ? '网络层 IPv6': '网络层 IPv4', range: ranges.l3, children: [
      { key: 'src', label: '源地址', value: p.srcIp ?? '—' },
      { key: 'dst', label: '目的地址', value: p.dstIp ?? '—' },
    ] })
  }
  if (p.transport === 'tcp' || p.transport === 'udp') {
    const flag: string = p.tcpFlags ? ' ' + tcpInfo(p.tcpFlags) : ''
    const tcpKids = p.transport === 'tcp'
      ? [
        { key: 'seq', label: 'Seq', value: p.tcpSeq != null ? String(p.tcpSeq) : '—' },
        { key: 'ack', label: 'Ack', value: p.tcpAck != null ? String(p.tcpAck) : '—' },
        { key: 'flags', label: '标志', value: p.tcpFlags ? tcpInfo(p.tcpFlags) : '—' },
        { key: 'analysis', label: '分析', value: p.tcpAnalysis?.join(', ') ?? '—' },
      ]
      : []
    nodes.push({ key: p.transport, label: (p.transport === 'tcp' ? '传输层 TCP' : '传输层 UDP') + flag, range: ranges[p.transport], children: [
      { key: 'sport', label: '源端口', value: p.srcPort != null ? String(p.srcPort) : '—' },
      { key: 'dport', label: '目的端口', value: p.dstPort != null ? String(p.dstPort) : '—' },
      ...tcpKids,
    ] })
  } else if (p.proto === 'arp') {
    nodes.push({ key: 'arp', label: 'ARP', range: ranges.arp, children: [
      { key: 'who', label: '识别', value: (p.srcMac ?? '—') + ' → ' + (p.dstMac ?? '—') },
    ] })
  }
  const appKids: DetailNode[] = []
  if (p.httpMethod != null || p.httpCode != null) {
    appKids.push({ key: 'http', label: p.httpMethod != null ? '方法 ' + p.httpMethod : '状态', value: p.httpMethod != null ? (p.httpUri ?? '/') : (p.httpCode ?? '') })
    appKids.push({ key: 'httpTime', label: '响应延迟', value: p.httpTime != null ? p.httpTime.toFixed(3) + 's' : '—' })
  }
  if (p.dnsQuery != null) {
    appKids.push({ key: 'dns', label: 'DNS 查询', value: p.dnsQuery })
  }
  if (p.tlsType != null) {
    appKids.push({ key: 'tls', label: 'TLS 握手类型', value: p.tlsType })
  }
  if (appKids.length) {
    nodes.push({ key: 'app', label: '应用层 ' + p.proto.toUpperCase(), range: ranges.app, children: appKids })
  }
  return nodes
}