import type { Conversation } from '../model/types'
import { displayHost } from '../model/types'

export interface TopologyNode {
  id: string
  x: number
  y: number
  host: string
  conversations: number
  bytes: number
  issues: number
}

export interface TopologyEdge {
  from: string
  to: string
  /** 唯一键:带 SEP 拼接,防 "1.1.1.1"+"23.0.0.5" 与 "1.1.1.12"+"3.0.0.5" 无分隔符碰撞 */
  key: string
  bytes: number
  protocols: string[]
  hasIssue: boolean
  convIds: string[]
}

export interface Topology {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

export const TOPO_W = 640
export const TOPO_H = 440

/** 多主机拓扑图(Top-N 会话图):取涉及字节最多的主机圆周均布,会话合并为边。
 *  Node 半径按会话数、边宽按字节对数,异常会话橙色描边。 */
export function buildTopology(convs: Conversation[], maxNodes = 24): Topology {
  // 1) 主机统计(endpoint 聚合,内联避免环形依赖)
  const hosts = new Map<string, { bytes: number; conversations: number; issues: number }>()
  const addHost = (h: string, bytes: number, issueCount: number) => {
    if (!h || h === '?') return
    let st = hosts.get(h)
    if (!st) { st = { bytes: 0, conversations: 0, issues: 0 }; hosts.set(h, st) }
    st.bytes += bytes
    st.conversations++
    st.issues += issueCount
  }
  for (const c of convs) {
    addHost(displayHost(c.client), c.bytes, c.issues.length)
    addHost(displayHost(c.server), c.bytes, c.issues.length)
  }
  const top = [...hosts.entries()]
    .sort((a, b) => b[1].bytes - a[1].bytes)
    .slice(0, maxNodes)
  const pos = new Map<string, { x: number; y: number }>()
  const nodes: TopologyNode[] = top.map(([host, st], i) => {
    // 起始角:默认从正上方起;仅 2 台主机时改为水平排列(0°/180° 竖排观感=一条竖线)
    const angle0 = top.length === 2 ? 0 : -Math.PI / 2
    const angle = (i / Math.max(top.length, 1)) * Math.PI * 2 + angle0
    const cx = TOPO_W / 2
    const cy = TOPO_H / 2
    const r = Math.min(TOPO_W, TOPO_H) / 2 - 46
    pos.set(host, { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r })
    return { id: host, x: pos.get(host)!.x, y: pos.get(host)!.y, host, conversations: st.conversations, bytes: st.bytes, issues: st.issues }
  })
  // 2) 会话 → 边,同主机对合并
  // 先对所有会话造边(Top-N 截断前不丢信息,便于合并统计),
  // 再按 nodes 集重过滤:边两端都必须在图内,否则渲染层 nodeById
  // 找不到坐标 → 无坐标 <line>(3 台截到 2 台时,指向被截主机的边被丢弃)。
  const nodeIds = new Set(nodes.map((n) => n.id))
  const edgeMap = new Map<string, TopologyEdge>()
  for (const c of convs) {
    const a = displayHost(c.client)
    const b = displayHost(c.server)
    if (a === b) continue
    const key = a < b ? a + SEP + b : b + SEP + a
    let e = edgeMap.get(key)
    if (!e) { e = { from: a, to: b, key, bytes: 0, protocols: [], hasIssue: false, convIds: [] }; edgeMap.set(key, e) }
    e.bytes += c.bytes
    if (!e.protocols.includes(c.protocol)) e.protocols.push(c.protocol)
    if (c.issues.length) e.hasIssue = true
    e.convIds.push(c.id)
  }
  const edges: TopologyEdge[] = [...edgeMap.values()]
    .filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to))
    .sort((a, b) => b.bytes - a.bytes)
  return { nodes, edges }
}

const SEP = '\u0000'