import type { Packet, Transport } from '../model/types'

interface RawJson {
  _source: { layers: Record<string, Record<string, string | string[]>> }
}

/** 解析文本上限:Rust 侧 MAX_CAPTURE_JSON(128MB)同档。JSON.parse 会把文本放大 4-8 倍
 *  成对象图(每帧数十个字段键),不加守卫会让 128MB 文本撑爆前端进程。 */
const MAX_PARSE_JSON = 128 * 1024 * 1024

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v
}

/** 取多值字段的全部取值:平铺(-e)模式下 tshark 把同名重复字段渲染成并行数组
 *  (如三块 SACK 的 sack_le = ["201","401","601"]),用 first() 会静默丢掉第 2..n 个。 */
function all(v: string | string[] | undefined): string[] {
  if (v == null) return []
  return Array.isArray(v) ? v : [v]
}

const FLAG_CHARS: Record<string, number> = { F: 0x01, S: 0x02, R: 0x04, P: 0x08, A: 0x10, U: 0x20 }

/** 由 tcp.flags.str 位串(如 "..S.A.")推出十六进制标志值 */
function flagsStrToHex(s: string | undefined): string | undefined {
  if (!s) return undefined
  let n = 0
  for (const ch of s) {
    const bit = FLAG_CHARS[ch]
    if (bit != null) n |= bit
  }
  return n ? `0x${n.toString(16).padStart(4, '0')}` : undefined
}

/** tcp.flags 兼容多种 tshark 输出形态:平铺字符串 / 数组 / 嵌套对象(jsonraw、旧版)。
 *  嵌套形态如 { 'tcp.flags': '0x0002', 'tcp.flags.str': '..S.' } → 取 hex;只有 str 时按位串推导。 */
function tcpFlagsHex(v: unknown): string | undefined {
  if (typeof v === 'string') return v
  if (Array.isArray(v)) return v.length ? tcpFlagsHex(v[0]) : undefined
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    const hex = tcpFlagsHex(o['tcp.flags'])
    if (hex != null) return hex
    return flagsStrToHex(tcpFlagsHex(o['tcp.flags.str']))
  }
  return undefined
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

/** TCP 分析标签字段:树形态键为连字符(如 tcp.analysis.lost-segment),-e 平铺形态为下划线
 *  (tcp.analysis.lost_segment,tshark -G fields 的规范名)。两种写法都探测。 */
const ANALYSIS_FIELDS: Array<[string, string]> = [
  ['tcp.analysis.retransmission', 'retransmission'],
  ['tcp.analysis.fast-retransmission', 'fast-retransmission'],
  ['tcp.analysis.fast_retransmission', 'fast-retransmission'],
  ['tcp.analysis.out-of-order', 'out-of-order'],
  ['tcp.analysis.out_of_order', 'out-of-order'],
  ['tcp.analysis.duplicate-ack', 'duplicate-ack'],
  ['tcp.analysis.duplicate_ack', 'duplicate-ack'],
  ['tcp.analysis.lost-segment', 'lost-segment'],
  ['tcp.analysis.lost_segment', 'lost-segment'],
  ['tcp.analysis.spurious-retransmission', 'spurious-retransmission'],
  ['tcp.analysis.spurious_retransmission', 'spurious-retransmission'],
]

/** SACK 块解析:平铺模式下左右边界是并行数组,按下标配对;
 *  树形态下 tshark 只保留最后一块(其 sack.count 仍是原始块数)。
 *  边界数量不匹配(截断/畸形)时只取成对的部分,宁可少报也不产出 NaN 污染序列空间运算。 */
function sackBlocks(le: string[], re: string[]): Array<[number, number]> | undefined {
  const n = Math.min(le.length, re.length)
  const out: Array<[number, number]> = []
  for (let i = 0; i < n; i++) {
    const l = Number.parseInt(le[i], 10)
    const r = Number.parseInt(re[i], 10)
    if (Number.isNaN(l) || Number.isNaN(r)) continue
    out.push([l, r])
  }
  return out.length ? out : undefined
}

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

/** 单帧字段访问器:兼容两种 tshark 输出形态——
 *  - 平铺(-T json -e):键直接在 layers 上,如 layers["ip.src"];
 *  - 协议树(-T json -J):键嵌在 layers.ip / layers.tcp 等子对象里(旧产物/旧 fixture)。
 *  统一经 get(field) 取值:先查平铺,再按字段前缀回落到对应协议树;
 *  树内允许任意嵌套(旧形态的 http request-line 键 / dns Queries / tcp.analysis 都是深嵌套)。
 *  深查代价用缓存兜底:同名字段每帧只递归一次。
 *  getRaw 供 tcp.flags 等可能为嵌套对象的字段使用(返回值交专用解析器处理)。 */
interface FrameFields {
  get: (field: string) => string | string[] | undefined
  getRaw: (field: string) => unknown
}

type FieldValue = string | string[] | Record<string, unknown>

function deepFind(layer: Record<string, unknown>, target: string): FieldValue | undefined {
  for (const [k, v] of Object.entries(layer)) {
    if (k === target) return v as FieldValue
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const r = deepFind(v as Record<string, unknown>, target)
      if (r !== undefined) return r
    }
  }
  return undefined
}

function makeFrameFields(L: Record<string, unknown>): FrameFields {
  const flat = L as Record<string, FieldValue>
  const cache = new Map<string, string | string[] | undefined>()
  const get = (field: string): string | string[] | undefined => {
    if (cache.has(field)) return cache.get(field)
    let v: string | string[] | undefined
    const raw = flat[field]
    if (typeof raw === 'string' || Array.isArray(raw)) {
      v = raw
    } else if (raw === undefined) {
      const dot = field.indexOf('.')
      // 平铺形态下协议名本身也可能是键(树形态);仅当值是对象才按树深查
      if (dot > 0) {
        const prefix = flat[field.slice(0, dot)]
        if (prefix && typeof prefix === 'object' && !Array.isArray(prefix)) {
          const found = deepFind(prefix as Record<string, unknown>, field)
          if (typeof found === 'string' || Array.isArray(found)) v = found
        }
      }
    }
    cache.set(field, v)
    return v
  }
  return {
    get,
    getRaw: (field) => {
      const direct = flat[field]
      if (direct !== undefined) return direct // 平铺直取(含 tcp.flags 嵌套对象形态)
      const dot = field.indexOf('.')
      if (dot <= 0) return undefined
      const prefix = flat[field.slice(0, dot)]
      if (!prefix || typeof prefix !== 'object' || Array.isArray(prefix)) return undefined
      return deepFind(prefix as Record<string, unknown>, field)
    },
  }
}

export function parsePackets(jsonText: string): Packet[] {
  if (jsonText.length > MAX_PARSE_JSON) {
    throw new Error(`抓包 JSON 过大(${(jsonText.length / 1024 / 1024).toFixed(1)}MB),请使用更小的抓包或先筛选`)
  }
  const data = JSON.parse(jsonText) as RawJson[]
  return data.map((entry, i) => {
    const F = makeFrameFields(entry._source.layers as Record<string, unknown>)
    return frameToPacket(F, i)
  })
}

/**
 * 分批解析(M5 流式):Rust 侧按帧边界分批回传,前端逐批 parse、逐批投影,
 * 单次 JSON.parse 的峰值内存从「整段文本+对象图」降为「单批文本+单批对象图」。
 *
 * Rust 批的真实形态(run_capture_stream 切帧语义,勿凭想象假设):
 * - 首批以 '[' 开头(整个输出数组的开括号随第一帧一起进来);
 * - 中间批以 ',' 开头(帧间逗号留在下一帧的切片头部);
 * - 末批以 ']' 结尾(EOF 冲尾,数组闭括号);
 * - 单批(输出 < 4MB)= 完整数组 '[...]'。
 * 因此这里必须清洗四类残片:前 '['、后 ']'、前后悬挂逗号,再包数组解析。
 * 帧号以**全局帧序**为回退(frame.number 缺失时),跨批用累计帧数偏移。
 */
export function parsePacketsBatchPush(state: { count: number }, batchText: string, out: Packet[]): void {
  let text = batchText.trim()
  if (text.startsWith('[')) text = text.slice(1)
  if (text.endsWith(']')) text = text.slice(0, -1)
  text = text.replace(/^\s*,/, '').replace(/,\s*$/, '').trim()
  if (text === '') return // 末批可能只剩 ']'
  const data = JSON.parse(`[${text}]`) as RawJson[]
  for (const entry of data) {
    const F = makeFrameFields(entry._source.layers as Record<string, unknown>)
    out.push(frameToPacket(F, state.count))
    state.count += 1
  }
}

/** 单帧字段访问器 -> Packet(主线程/Worker/分批三路共用的投影,帧号回退用全局帧序) */
function frameToPacket(F: ReturnType<typeof makeFrameFields>, fallbackIndex: number): Packet {
  const protocols = (first(F.get('frame.protocols')) ?? '').split(':').filter((s) => s !== '')
  const transport = transportOf(protocols)
  const srcIp = first(F.get('ip.src')) ?? first(F.get('ipv6.src'))
  const dstIp = first(F.get('ip.dst')) ?? first(F.get('ipv6.dst'))
  const srcPort = int(F.get('tcp.srcport')) ?? int(F.get('udp.srcport'))
  const dstPort = int(F.get('tcp.dstport')) ?? int(F.get('udp.dstport'))
  const proto = appProto(protocols)
  const reqLine = first(F.get('http.request.line'))
  const resLine = first(F.get('http.response.line'))
  const analysisTags: string[] = []
  for (const [field, tag] of ANALYSIS_FIELDS) {
    // 去重两种来源的重复:①同一标签的连字符/下划线两种字段名都命中;
    // ②平铺模式下单个 dup ACK 报文的 duplicate_ack 值是 ["1","1"](实测),
    // 按数组条目计数会让重复 ACK 数翻倍 —— 标签只表示"该报文有此现象",按报文计一次
    if (F.get(field) != null && !analysisTags.includes(tag)) analysisTags.push(tag)
  }
  const dnsResp = first(F.get('dns.flags.response'))
  // SMB2 响应标志三态:仅 1/true(大小写不敏感,-e 形态为 True/False)视为 true;
  // false = 字段存在但是请求,undefined = 字段缺失 —— 分析器按 false/undefined 都当请求,
  // 但保留三态语义避免把「字段缺失」误记成「确认为请求」
  const smb2Resp = first(F.get('smb2.flags.response'))
  const base: Pick<Packet, 'proto' | 'tcpFlags' | 'httpMethod' | 'httpUri' | 'httpCode' | 'dnsQuery' | 'transport'> = {
    proto,
    transport,
    tcpFlags: tcpFlagsHex(F.getRaw('tcp.flags')),
    httpMethod: first(F.get('http.request.method')) ?? parseRequestLine(reqLine).method,
    httpUri: first(F.get('http.request.uri')) ?? parseRequestLine(reqLine).uri,
    httpCode: first(F.get('http.response.code')) ?? parseResponseCode(resLine),
    dnsQuery: first(F.get('dns.qry.name')),
  }
  return {
    number: int(F.get('frame.number')) ?? fallbackIndex + 1,
    time: float(F.get('frame.time_relative')) ?? 0,
    timeEpoch: float(F.get('frame.time_epoch')),
    interfaceId: first(F.get('frame.interface_id')),
    len: int(F.get('frame.len')) ?? 0,
    capLen: int(F.get('frame.cap_len')),
    transport,
    proto,
    srcIp,
    dstIp,
    srcMac: first(F.get('eth.src')),
    dstMac: first(F.get('eth.dst')),
    srcPort,
    dstPort,
    tcpFlags: base.tcpFlags,
    tcpSeq: float(F.get('tcp.seq_raw')),
    tcpAck: float(F.get('tcp.ack_raw')),
    tcpStream: int(F.get('tcp.stream')),
    tcpLen: int(F.get('tcp.len')),
    tcpWindow: int(F.get('tcp.window_size')),
    tcpCompleteness: int(F.get('tcp.completeness')),
    tcpSackBlocks: sackBlocks(all(F.get('tcp.options.sack_le')), all(F.get('tcp.options.sack_re'))),
    tcpDupAckNum: int(F.get('tcp.analysis.duplicate_ack_num')) ?? int(F.get('tcp.analysis.duplicate-ack-num')),
    tcpAnalysis: analysisTags.length ? analysisTags : undefined,
    httpTime: float(F.get('http.time')),
    httpMethod: base.httpMethod,
    httpUri: base.httpUri,
    httpCode: base.httpCode,
    dnsQuery: base.dnsQuery,
    tlsType: first(F.get('tls.handshake.type')),
    // M6 第二批:SSH/RDP/VNC/SMB 明文字段直取(first 取首值);字段缺失即 undefined,不臆造
    sshProtocol: first(F.get('ssh.protocol')),
    sshChannelType: first(F.get('ssh.connection_type_name')),
    rdpNegProtocols: first(F.get('rdp.negReq.requestedProtocols')),
    rdpClientName: first(F.get('rdp.client.name')),
    vncProtoVer: first(F.get('vnc.server_proto_ver')),
    smb2Cmd: first(F.get('smb2.cmd')),
    smb2Response: smb2Resp == null ? undefined : /^(?:1|true)$/i.test(smb2Resp),
    smb2Tree: first(F.get('smb2.tree')),
    // dns.flags.response:树形态为 "0"/"1",-e 形态为 "False"/"True",两者都识别
    info: makeInfo({ ...base, info: dnsResp === '1' || dnsResp === 'True' ? 'response' : undefined }),
    direction: 'other',
  }
}
