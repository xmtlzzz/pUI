import type { Packet } from '../../model/types'

/**
 * M6 ApplicationAnalyzer 插件接口(plan §M6):业务层协议分析器以纯函数插件挂载,
 * 每个分析器只消费 Packet 上已解析的字段(http./dns./tls. 前缀,在 M0 字段契约内),
 * 不做任何解密与深度重组 —— 声明能力边界是红线。
 *
 * 输出 AppEvent 是观察层事实(何时何包发生了什么应用层交互),
 * 措辞与 TCP 事件同红线:不归因、不断言因果;因果性关联由 impact 层
 * 以时间窗重叠 + 限定措辞承担。
 */

/** 应用层事件(观察事实) */
export interface AppEvent {
  /** 确定性 id:`${app}:${kind}:${packetNumber}` */
  id: string
  /** 协议族:http / dns / tls */
  app: 'http' | 'dns' | 'tls'
  /** 事件类别:request / response / query / response(query 侧) / handshake */
  kind: 'request' | 'response' | 'query' | 'handshake'
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

/** 插件注册表:第一批 HTTP/DNS/TLS。新增协议在此追加,UI 自动获得计数与事件。 */
export const APPLICATION_ANALYZERS: readonly ApplicationAnalyzer[] = [httpAnalyzer, dnsAnalyzer, tlsAnalyzer]

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
