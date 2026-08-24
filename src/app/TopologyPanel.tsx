import { useMemo, useRef, useState } from 'react'
import { useApp } from '../state/appStore'
import { buildTopology, TOPO_W, TOPO_H, type TopologyNode } from '../stats/topology'
import { fmtBytesShort } from './topoUtil'

/** 左侧「拓扑」面板:Top-N 主机会话图,边宽按字节对数,异常橙色虚线;点击边跳到对应会话 */
export function TopologyPanel() {
  const conversations = useApp((s) => s.conversations)
  const select = useApp((s) => s.select)
  const topo = useMemo(() => buildTopology(conversations), [conversations])
  // 轻量平移:仅视图位移,无缩放/节点拖动/3D
  const [view, setView] = useState({ x: 16, y: 8 })
  const pan = useRef<{ sx: number; sy: number; bx: number; by: number } | null>(null)

  const startPan = (e: React.PointerEvent) => {
    // jsdom 无此 API,真实浏览器才需要(测试环境跳过即可)
    if (typeof e.currentTarget.setPointerCapture === 'function') e.currentTarget.setPointerCapture(e.pointerId)
    pan.current = { sx: e.clientX, sy: e.clientY, bx: view.x, by: view.y }
  }
  const movePan = (e: React.PointerEvent) => {
    const p = pan.current
    if (!p) return
    setView((v) => ({ ...v, x: p.bx + (e.clientX - p.sx), y: p.by + (e.clientY - p.sy) }))
  }
  const endPan = (e: React.PointerEvent) => {
    pan.current = null
    try { e.currentTarget.releasePointerCapture(e.pointerId) } catch { /* noop */ }
  }

  if (!topo.nodes.length) {
    return <div className="empty">打开文件后显示主机拓扑</div>
  }
  if (topo.nodes.length === 1) {
    return <div className="empty">会话集中在单台主机,无需拓扑展示</div>
  }
  const maxBytes = Math.max(...topo.edges.map((e) => e.bytes), 1)
  const maxConvs = Math.max(...topo.nodes.map((n) => n.conversations), 1)
  return (
    <div className="topo-wrap">
      <div className="pane-title">主机拓扑 ({topo.nodes.length} 主机 · {topo.edges.length} 边)</div>
      <svg
        viewBox={`0 0 ${TOPO_W} ${TOPO_H}`}
        className="topo-svg"
        onPointerDown={startPan}
        onPointerMove={movePan}
        onPointerUp={endPan}
        onPointerCancel={endPan}
      >
        <g transform={`translate(${view.x} ${view.y})`}>
          {topo.edges.map((e) => (
          <line
            key={e.key}
            x1={nodeById(topo.nodes, e.from)?.x}
            y1={nodeById(topo.nodes, e.from)?.y}
            x2={nodeById(topo.nodes, e.to)?.x}
            y2={nodeById(topo.nodes, e.to)?.y}
            stroke={e.hasIssue ? '#f59e0b' : '#cbd5e1'}
            strokeWidth={e.hasIssue ? Math.max(2.5, 1 + Math.log2(1 + e.bytes / maxBytes) * 3) : Math.max(1, Math.log2(1 + e.bytes / maxBytes) * 3)}
            strokeDasharray={e.hasIssue ? '5,3' : undefined}
            className="topo-edge"
            onClick={() => select(e.convIds[0])}
          >
            <title>
              {e.from} ⇄ {e.to} · {fmtBytesShort(e.bytes)} · {e.protocols.join(',')}{e.hasIssue ? ' · ⚠异常' : ''}
            </title>
          </line>
        ))}
        {topo.nodes.map((n) => (
          <g key={n.id} className="topo-node" transform={`translate(${n.x} ${n.y})`}>
            <circle
              r={6 + (n.conversations / maxConvs) * 9}
              fill={n.issues ? '#fff7ed' : '#eff6ff'}
              stroke={n.issues ? '#ea580c' : '#3b82f6'}
              strokeWidth={2}
            />
            <text y={-(6 + (n.conversations / maxConvs) * 9) - 4} textAnchor="middle" fontSize={10} fill="#334155">
              {n.host}
            </text>
          </g>
        ))}
        </g>
      </svg>
      <div className="topo-hint">拖拽平移 · 点击边查看对应会话;节点大小 = 会话数,边宽 = 字节量,橙色虚线 = 含异常</div>
    </div>
  )
}

function nodeById(nodes: TopologyNode[], id: string): TopologyNode | undefined {
  return nodes.find((n) => n.id === id)
}
