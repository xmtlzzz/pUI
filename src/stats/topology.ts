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
    const angle = (i / Math.max(top.length, 1)) * Math.PI * 2 - Math.PI / 2
    const cx = TOPO_W / 2
    const cy = TOPO_H / 2
    const r = Math.min(TOPO_W, TOPO_H) / 2 - 46
    pos.set(host, { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r })
    return { id: host, x: pos.get(host)!.x, y: pos.get(host)!.y, host, conversations: st.conversations, bytes: st.bytes, issues: st.issues }
  })
  // 2) 会话 → 边,同主机对合并
  const edgeMap = new Map<string, TopologyEdge>()
  for (const c of convs) {
    const a = displayHost(c.client)
    const b = displayHost(c.server)
    if (a === b || !pos.has(a) || !pos.has(b)) continue
    const key = a < b ? a + SEP + b : b + SEP + a
    let e = edgeMap.get(key)
    if (!e) { e = { from: a, to: b, bytes: 0, protocols: [], hasIssue: false, convIds: [] }; edgeMap.set(key, e) }
    e.bytes += c.bytes
    if (!e.protocols.includes(c.protocol)) e.protocols.push(c.protocol)
    if (c.issues.length) e.hasIssue = true
    e.convIds.push(c.id)
  }
  const edges: TopologyEdge[] = [...edgeMap.values()].sort((a, b) => b.bytes - a.bytes)
  return { nodes, edges }
}

const SEP = '\u0000'