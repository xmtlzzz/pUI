import type { Packet, Transport } from '../model/types'

interface RawJson {
  _source: { layers: Record<string, Record<string, string | string[]>> }
}

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v
}
function int(v: string | string[] | undefined): number | undefined {
  const s = first(v)
  if (s == null) return undefined
  const n = Number.parseInt(s, 10)
  return Number.isNaN(n) ? undefined : n
}
function float(v: string | string[] | undefined): number | undefined {
  const s = first(v)
  if (s == null) return undefined
  const n = Number.parseFloat(s)
  return Number.isNaN(n) ? undefined : n
}

const IGNORED_STACK = new Set([
  'eth', 'ethertype', 'ip', 'ipv6', 'llc', 'sll', 'raw', 'data',
  'data-text-lines', 'text-lines', 'tcp.segments', 'reassembled.tcp', '_ws.malformed',
])

const ANALYSIS_FIELDS: Array<[string, string]> = [
  ['tcp.analysis.retransmission', 'retransmission'],
  ['tcp.analysis.fast-retransmission', 'fast-retransmission'],
  ['tcp.analysis.out-of-order', 'out-of-order'],
  ['tcp.analysis.duplicate-ack', 'duplicate-ack'],
  ['tcp.analysis.lost-segment', 'lost-segment'],
]

function appProto(protocols: string[]): string {
  for (let i = protocols.length - 1; i >= 0; i--) {
    const seg = protocols[i].toLowerCase()
    if (!IGNORED_STACK.has(seg)) return seg
  }
  return protocols[protocols.length - 1]?.toLowerCase() ?? 'unknown'
}

function transportOf(protocols: string[]): Transport {
  if (protocols.includes('tcp')) return 'tcp'
  if (protocols.includes('udp')) return 'udp'
  if (protocols.includes('icmp')) return 'icmp'
  if (protocols.includes('arp')) return 'arp'
  return 'other'
}

export function tcpInfo(flagsHex: string | undefined): string {
  if (!flagsHex) return 'TCP'
  const n = Number.parseInt(flagsHex, 16)
  if (Number.isNaN(n)) return 'TCP'
  const parts: string[] = []
  if (n & 0x01) parts.push('FIN')
  if (n & 0x02) parts.push('SYN')
  if (n & 0x04) parts.push('RST')
  if (n & 0x08) parts.push('PSH')
  if (n & 0x10) parts.push('ACK')
  if (n & 0x20) parts.push('URG')
  return parts.length ? `TCP ${parts.join('-')}` : 'TCP'
}

export function makeInfo(
  p: Pick<Packet, 'proto' | 'tcpFlags' | 'httpMethod' | 'httpUri' | 'httpCode' | 'dnsQuery' | 'transport' | 'info'>,
): string | undefined {
  if (p.proto === 'http' && p.httpMethod) return `HTTP ${p.httpMethod} ${p.httpUri ?? ''}`.trim()
  if (p.proto === 'http' && p.httpCode) return `HTTP ${p.httpCode}`
  if (p.proto === 'dns' && p.dnsQuery) return `DNS ${p.info ?? 'query'}: ${p.dnsQuery}`
  if (p.proto === 'dns') return `DNS ${p.info ?? 'packet'}`
  if (p.transport === 'tcp') return tcpInfo(p.tcpFlags)
  if (p.proto === 'icmp') return 'ICMP'
  if (p.proto === 'arp') return 'ARP'
  return p.proto.toUpperCase()
}

function deepFind(layer: Record<string, unknown>, target: string): string | undefined {
  for (const [k, v] of Object.entries(layer)) {
    if (k === target) {
      if (Array.isArray(v)) return typeof v[0] === 'string' ? v[0] : undefined
      return typeof v === 'string' ? v : undefined
    }
    if (v && typeof v === 'object') {
      const r = deepFind(v as Record<string, unknown>, target)
      if (r != null) return r
    }
  }
  return undefined
}

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'])

function parseRequestLine(line: string | undefined): { method?: string; uri?: string } {
  if (!line) return {}
  const parts = line.split(/\s+/)
  if (parts.length >= 2 && HTTP_METHODS.has(parts[0])) return { method: parts[0], uri: parts[1] }
  return {}
}

function parseResponseCode(line: string | undefined): string | undefined {
  if (!line) return undefined
  const parts = line.split(/\s+/)
  return parts[0]?.startsWith('HTTP/') ? parts[1] : undefined
}

export function parsePackets(jsonText: string): Packet[] {
  const data = JSON.parse(jsonText) as RawJson[]
  return data.map((entry, i) => {
    const L = entry._source.layers
    const frame = L['frame'] ?? {}
    const eth = L['eth'] ?? {}
    const ip = L['ip'] ?? {}
    const ipv6 = L['ipv6'] ?? {}
    const tcp = L['tcp'] ?? {}
    const udp = L['udp'] ?? {}
    const http = L['http'] ?? {}
    const dns = L['dns'] ?? {}
    const tls = L['tls'] ?? {}
    const protocols = (first(frame['frame.protocols']) ?? '').split(':')
    const transport = transportOf(protocols)
    const srcIp = first(ip['ip.src']) ?? first(ipv6['ipv6.src'])
    const dstIp = first(ip['ip.dst']) ?? first(ipv6['ipv6.dst'])
    const srcPort = int(tcp['tcp.srcport']) ?? int(udp['udp.srcport'])
    const dstPort = int(tcp['tcp.dstport']) ?? int(udp['udp.dstport'])
    const proto = appProto(protocols)
    const reqLine = first(http['http.request.line'])
    const resLine = first(http['http.response.line'])
    const analysisTags: string[] = []
    for (const [field, tag] of ANALYSIS_FIELDS) {
      if (deepFind(tcp, field) != null) analysisTags.push(tag)
    }
    const base: Pick<Packet, 'proto' | 'tcpFlags' | 'httpMethod' | 'httpUri' | 'httpCode' | 'dnsQuery' | 'transport'> = {
      proto,
      transport,
      tcpFlags: first(tcp['tcp.flags']),
      httpMethod: deepFind(http, 'http.request.method') ?? parseRequestLine(reqLine).method,
      httpUri: deepFind(http, 'http.request.uri') ?? parseRequestLine(reqLine).uri,
      httpCode: deepFind(http, 'http.response.code') ?? parseResponseCode(resLine),
      dnsQuery: deepFind(dns, 'dns.qry.name'),
    }
    return {
      number: int(frame['frame.number']) ?? i + 1,
      time: float(frame['frame.time_relative']) ?? 0,
      len: int(frame['frame.len']) ?? 0,
      transport,
      proto,
      srcIp,
      dstIp,
      srcMac: first(eth['eth.src']),
      dstMac: first(eth['eth.dst']),
      srcPort,
      dstPort,
      tcpFlags: base.tcpFlags,
      tcpSeq: float(tcp['tcp.seq_raw']),
      tcpAck: float(tcp['tcp.ack_raw']),
      tcpAnalysis: analysisTags.length ? analysisTags : undefined,
      httpTime: float(http['http.time']),
      httpMethod: base.httpMethod,
      httpUri: base.httpUri,
      httpCode: base.httpCode,
      dnsQuery: base.dnsQuery,
      tlsType: first(tls['tls.handshake.type']),
      info: makeInfo({ ...base, info: deepFind(dns, 'dns.flags.response') === '1' ? 'response' : undefined }),
      direction: 'other',
    }
  })
}
