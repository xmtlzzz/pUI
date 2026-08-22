import type { Packet } from '../model/types'
import { tcpInfo } from '../parse/parsePackets'

export interface DetailNode {
  key: string
  label: string // 行文本
  value?: string
  children?: DetailNode[]
}

/** 报文详情分层树(帧 → L2 → L3 → L4 → 应用层):按层级组织字段,可折叠展示 */
export function buildPacketTree(p: Packet): DetailNode[] {
  const nodes: DetailNode[] = []
  nodes.push({ key: 'frame', label: '帧 Frame', children: [
    { key: 'no', label: '编号', value: String(p.number) },
    { key: 'time', label: '相对时间', value: p.time.toFixed(3) + 's' },
    { key: 'timeAbs', label: '绝对时间', value: p.timeEpoch != null ? new Date(p.timeEpoch * 1000).toLocaleString() : '—' },
    { key: 'len', label: '长度', value: p.len + 'B' },
    { key: 'iface', label: '接口', value: p.interfaceId != null ? '#' + p.interfaceId : '—' },
    { key: 'dir', label: '方向', value: p.direction === 'request' ? '请求' : p.direction === 'response' ? '响应' : '其他' },
  ] })
  if (p.srcMac || p.dstMac) {
    nodes.push({ key: 'l2', label: '以太网 L2', children: [
      { key: 'src', label: '源 MAC', value: p.srcMac ?? '—' },
      { key: 'dst', label: '目的 MAC', value: p.dstMac ?? '—' },
    ] })
  }
  if (p.srcIp || p.dstIp) {
    const isV6 = (p.srcIp?.includes(':') ?? false) || (p.dstIp?.includes(':') ?? false)
    nodes.push({ key: 'l3', label: isV6 ? '网络层 IPv6': '网络层 IPv4', children: [
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
    nodes.push({ key: p.transport, label: (p.transport === 'tcp' ? '传输层 TCP' : '传输层 UDP') + flag, children: [
      { key: 'sport', label: '源端口', value: p.srcPort != null ? String(p.srcPort) : '—' },
      { key: 'dport', label: '目的端口', value: p.dstPort != null ? String(p.dstPort) : '—' },
      ...tcpKids,
    ] })
  } else if (p.proto === 'arp') {
    nodes.push({ key: 'arp', label: 'ARP', children: [
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
    nodes.push({ key: 'app', label: '应用层 ' + p.proto.toUpperCase(), children: appKids })
  }
  return nodes
}