import type { Packet } from '../../model/types'

/**
 * M6 ApplicationAnalyzer 插件接口(plan §M6):业务层协议分析器以纯函数插件挂载,
 * 每个分析器只消费 Packet 上已解析的字段(http./dns./tls./ssh./rdp./vnc./smb2. 前缀,
 * 在 M0 起步的字段契约内),不做任何解密与深度重组 —— 声明能力边界是红线。
 *
 * 输出 AppEvent 是观察层事实(何时何包发生了什么应用层交互),
 * 措辞与 TCP 事件同红线:不归因、不断言因果;因果性关联由 impact 层
 * 以时间窗重叠 + 限定措辞承担。
 */

/** 应用层事件(观察事实) */
export interface AppEvent {
  /** 确定性 id:`${app}:${kind}:${packetNumber}` */
  id: string
  /** 协议族:http / dns / tls / ssh / rdp / vnc / smb */
  app: 'http' | 'dns' | 'tls' | 'ssh' | 'rdp' | 'vnc' | 'smb'
  /** 事件类别:request / response / query / response(query 侧) / handshake / session(SSH 通道请求) */
  kind: 'request' | 'response' | 'query' | 'handshake' | 'session'
  packetNumber: number
  time: number
  /** 观察层摘要,如「HTTP GET /api/data」「DNS 查询 example.com」 */
  summary: string
  /** HTTP 请求到响应耗时(http.time,秒);仅 response 事件携带,缺失=字段不可用 */
  durationSeconds?: number
}

/** 应用层分析器插件:实现本接口并注册进 APPLICATION_ANALYZERS 即生效 */
export interface ApplicationAnalyzer {
  /** 插件 id(稳定,入事件 id) */
  id: string
  /** 展示名(摘要面板图例) */
  label: string
  /** 纯函数:同一输入永远同一输出;无事件返回空数组 */
  analyze(packets: Packet[]): AppEvent[]
}

/** URI 摘要截断:超长路径只保留查询串前的主体(摘要层不承载全文) */
function trimUri(uri: string | undefined, max = 48): string {
  if (!uri) return ''
  return uri.length > max ? `${uri.slice(0, max)}…` : uri
}

/** 通用摘要截断:超长加省略号(SSH 横幅/树路径等;摘要层不承载全文) */
function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s
}

/** HTTP 分析器:请求/响应(响应携带 http.time 耗时观察)。无法配对的请求不臆造响应。 */
export const httpAnalyzer: ApplicationAnalyzer = {
  id: 'http',
  label: 'HTTP',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.httpMethod != null) {
        out.push({
          id: `http:request:${p.number}`,
          app: 'http',
          kind: 'request',
          packetNumber: p.number,
          time: p.time,
          summary: `HTTP ${p.httpMethod} ${trimUri(p.httpUri)}`.trimEnd(),
        })
      }
      if (p.httpCode != null) {
        out.push({
          id: `http:response:${p.number}`,
          app: 'http',
          kind: 'response',
          packetNumber: p.number,
          time: p.time,
          // http.time 是 tshark 统计的请求到响应耗时;undefined = 字段缺失(如实省略)
          summary: `HTTP 响应 ${p.httpCode}`,
          durationSeconds: p.httpTime,
        })
      }
    }
    return out
  },
}

/** DNS 分析器:查询/响应。query 名称截断防超长域名撑爆摘要。 */
export const dnsAnalyzer: ApplicationAnalyzer = {
  id: 'dns',
  label: 'DNS',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.dnsQuery == null) continue
      const isResp = p.info?.includes('response') ?? false
      const name = p.dnsQuery.length > 40 ? `${p.dnsQuery.slice(0, 40)}…` : p.dnsQuery
      out.push({
        id: `dns:${isResp ? 'response' : 'query'}:${p.number}`,
        app: 'dns',
        kind: 'query',
        packetNumber: p.number,
        time: p.time,
        summary: isResp ? `DNS 响应 ${name}` : `DNS 查询 ${name}`,
      })
    }
    return out
  },
}

/** TLS 握手类型常见值(tls.handshake.type;未列出的按编号如实显示) */
const TLS_HANDSHAKE_NAMES: Record<string, string> = {
  '1': 'ClientHello',
  '2': 'ServerHello',
  '4': 'NewSessionTicket',
  '11': 'Certificate',
  '12': 'ServerKeyExchange',
  '13': 'CertificateRequest',
  '14': 'ServerHelloDone',
  '15': 'CertificateVerify',
  '16': 'ClientKeyExchange',
}

/** TLS 分析器:仅握手存在性观察(字段只暴露 handshake.type;不做解密——也没有密钥) */
export const tlsAnalyzer: ApplicationAnalyzer = {
  id: 'tls',
  label: 'TLS',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.tlsType == null) continue
      const name = TLS_HANDSHAKE_NAMES[p.tlsType] ?? `type=${p.tlsType}`
      out.push({
        id: `tls:handshake:${p.number}`,
        app: 'tls',
        kind: 'handshake',
        packetNumber: p.number,
        time: p.time,
        summary: `TLS 握手 ${name}`,
      })
    }
    return out
  },
}

/** RDP 连接协商请求协议位:0x1=SSL 0x2=CredSSP(hybrid) 0x4=RDSTLS 0x8=HybridEx(CredSSP 扩展)。
 *  位值按 tshark 4.6.6 -G fields 实测注册(rdstls=0x4/hybrid_ex=0x8);未命中已知位时
 *  由调用方按原文如实显示,不在观察层臆造名称 */
const RDP_NEG_PROTOCOL_BITS: ReadonlyArray<readonly [number, string]> = [
  [0x1, 'SSL'],
  [0x2, 'CredSSP'],
  [0x4, 'RDSTLS'],
  [0x8, 'CredSSP扩展'],
]

/** 解析 requestedProtocols 掩码文本:tshark 实测输出形如 0x00000003(十六进制),
 *  同时容错纯十进制两种形态;解析不了(非数字/超出安全整数)返回 undefined,
 *  由调用方按原始文本如实显示 —— 不猜测安全级别。 */
function parseRdpNegBits(raw: string): string | undefined {
  const n = /^0[xX][0-9a-fA-F]+$/.test(raw)
    ? Number.parseInt(raw.slice(2), 16)
    : /^\d+$/.test(raw)
      ? Number.parseInt(raw, 10)
      : Number.NaN
  if (!Number.isSafeInteger(n) || n < 0) return undefined
  const hits = RDP_NEG_PROTOCOL_BITS.filter(([bit]) => (n & bit) !== 0).map(([, name]) => name)
  return hits.length ? hits.join('+') : undefined
}

/** RDP 分析器:仅观察 X.224 连接协商与明文客户端名。
 *  加密边界:协商完成即进入加密虚拟通道,键盘/屏幕/剪贴板数据不可见,不做安全级别归因。 */
export const rdpAnalyzer: ApplicationAnalyzer = {
  id: 'rdp',
  label: 'RDP',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.rdpNegProtocols != null) {
        // 解析失败(或无已知位命中)时按原始文本如实显示,不臆造协议名
        const bits = parseRdpNegBits(p.rdpNegProtocols) ?? p.rdpNegProtocols
        out.push({
          id: `rdp:handshake:${p.number}`,
          app: 'rdp',
          kind: 'handshake',
          packetNumber: p.number,
          time: p.time,
          summary: `RDP 连接协商 请求协议=${bits}`,
        })
      }
      if (p.rdpClientName != null) {
        out.push({
          id: `rdp:session:${p.number}`,
          app: 'rdp',
          kind: 'session',
          packetNumber: p.number,
          time: p.time,
          summary: `RDP 客户端名 ${truncate(p.rdpClientName, 40)}`,
        })
      }
    }
    return out
  },
}

/** SSH 分析器:仅观察明文版本横幅与通道请求类型名。
 *  加密边界:密钥交换后 SSH 全程加密,通道内命令/传输数据不可见,摘要只到横幅/通道类型粒度。 */
export const sshAnalyzer: ApplicationAnalyzer = {
  id: 'ssh',
  label: 'SSH',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.sshProtocol != null) {
        out.push({
          id: `ssh:handshake:${p.number}`,
          app: 'ssh',
          kind: 'handshake',
          packetNumber: p.number,
          time: p.time,
          summary: `SSH 版本横幅 ${truncate(p.sshProtocol, 40)}`,
        })
      }
      if (p.sshChannelType != null) {
        out.push({
          id: `ssh:session:${p.number}`,
          app: 'ssh',
          kind: 'session',
          packetNumber: p.number,
          time: p.time,
          summary: `SSH 通道请求 ${p.sshChannelType}`,
        })
      }
    }
    return out
  },
}

/** VNC 分析器:仅观察 RFB 版本横幅。
 *  加密边界:RFB 3.8 常见握手后进入各安全类型的加密/认证通道,security 类型字段实测不落值,
 *  故不做安全级别归因;字段缺失即不产出事件。 */
export const vncAnalyzer: ApplicationAnalyzer = {
  id: 'vnc',
  label: 'VNC',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.vncProtoVer == null) continue
      out.push({
        id: `vnc:handshake:${p.number}`,
        app: 'vnc',
        kind: 'handshake',
        packetNumber: p.number,
        time: p.time,
        summary: `VNC RFB 版本 ${p.vncProtoVer}`,
      })
    }
    return out
  },
}

/** SMB2 命令号 → 名称(tshark 十进制输出;未列出的按「命令 n」如实显示,不臆造语义) */
const SMB2_COMMAND_NAMES: Record<string, string> = {
  '0': '协商',
  '1': '会话建立',
  '2': '会话注销',
  '3': '树连接',
  '4': '树断开',
  '5': '创建',
  '6': '读取',
  '7': '写入',
  '16': '关闭',
  '18': '枚举',
  '22': '设置信息',
}

/** SMB 分析器:仅观察 SMB2 明文命令号与树路径。
 *  加密边界:会话建立后载荷(含文件名)加密,smb2.filename 未纳入契约,摘要只到 tree 粒度;
 *  无响应标志字段时按请求处理(方向未知 ≠ 臆造响应)。 */
export const smbAnalyzer: ApplicationAnalyzer = {
  id: 'smb',
  label: 'SMB',
  analyze(packets: Packet[]): AppEvent[] {
    const out: AppEvent[] = []
    for (const p of packets) {
      if (p.smb2Cmd == null) continue
      const kind: AppEvent['kind'] = p.smb2Response ? 'response' : 'request'
      const tree = p.smb2Tree != null ? ` ${truncate(p.smb2Tree, 48)}` : ''
      out.push({
        id: `smb:${kind}:${p.number}`,
        app: 'smb',
        kind,
        packetNumber: p.number,
        time: p.time,
        summary: `SMB2 ${SMB2_COMMAND_NAMES[p.smb2Cmd] ?? `命令 ${p.smb2Cmd}`}${tree}`,
      })
    }
    return out
  },
}

/** 插件注册表:第一批 HTTP/DNS/TLS + 第二批 SSH/RDP/VNC/SMB。新增协议在此追加,UI 自动获得计数与事件。 */
export const APPLICATION_ANALYZERS: readonly ApplicationAnalyzer[] = [
  httpAnalyzer,
  dnsAnalyzer,
  tlsAnalyzer,
  sshAnalyzer,
  rdpAnalyzer,
  vncAnalyzer,
  smbAnalyzer,
]

/** 运行全部已注册分析器,按时间排序(时间相同按 id 兜底,完全确定)。 */
export function runApplicationAnalyzers(packets: Packet[]): AppEvent[] {
  const out: AppEvent[] = []
  for (const a of APPLICATION_ANALYZERS) out.push(...a.analyze(packets))
  return out.sort((x, y) => x.time - y.time || x.id.localeCompare(y.id))
}

/** 应用层事件计数(摘要面板网格):按 app×kind 汇总 + 慢响应数由调用方按阈值另计 */
export function countAppEvents(events: AppEvent[]): Array<{ app: string; kind: string; count: number }> {
  const m = new Map<string, number>()
  for (const e of events) {
    const k = `${e.app}:${e.kind}`
    m.set(k, (m.get(k) ?? 0) + 1)
  }
  return [...m.entries()].map(([k, count]) => {
    const [app, kind] = k.split(':')
    return { app, kind, count }
  })
}
