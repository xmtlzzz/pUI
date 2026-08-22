import { useMemo, useRef, useState } from 'react'
import { useApp } from '../state/appStore'
import { buildTopology, TOPO_W, TOPO_H } from '../stats/topology'
import { fmtBytesShort } from './topoUtil'
import { Topology3D } from './Topology3D'

/** 画布视图:平移 + 缩放;节点可拖拽重排 */
interface View { x: number; y: number; zoom: number }

/** 左侧「拓扑」面板:2D 可拖拽拓扑 + three.js 3D 视角切换。
 *  2D:拖拽空白平移、滚轮缩放、拖节点布局、点击边选会话;3D:OrbitControls 旋转缩放。 */
export function TopologyPanel() {
  const conversations = useApp((s) => s.conversations)
  const select = useApp((s) => s.select)
  const topo = useMemo(() => buildTopology(conversations), [conversations])
  const [dim, setDim] = useState<'2d' | '3d'>('2d')
  const [view, setView] = useState<View>({ x: 16, y: 8, zoom: 1 })
  const [nodePos, setNodePos] = useState<Record<string, { x: number; y: number }>>({})
  const svgRef = useRef<SVGSVGElement | null>(null)
  const pan = useRef<{ sx: number; sy: number; bx: number; by: number; node?: string } | null>(null)

  if (!topo.nodes.length) {
    return <div className="empty">打开文件后显示主机拓扑</div>
  }
  if (topo.nodes.length === 1) {
    return <div className="empty">会话集中在单台主机,无需拓扑展示</div>
  }

  // 节点拖拽覆盖合并;边坐标基于覆盖后的位置
  const renderNodes = useMemo(
    () => topo.nodes.map((n) => (nodePos[n.id] ? { ...n, x: nodePos[n.id].x, y: nodePos[n.id].y } : n)),
    [topo, nodePos],
  )
  const findNode = (id: string) => renderNodes.find((n) => n.id === id)

  const toSvg = (clientX: number, clientY: number): { x: number; y: number } => {
    const rect = svgRef.current?.getBoundingClientRect()
    const px = rect ? clientX - rect.left : clientX
    const py = rect ? clientY - rect.top : clientY
    return { x: (px - view.x) / view.zoom, y: (py - view.y) / view.zoom }
  }

  const startPan = (e: React.PointerEvent) => {
    // jsdom 无此 API,真实浏览器才需要(测试环境跳过即可)
    if (typeof e.currentTarget.setPointerCapture === 'function') e.currentTarget.setPointerCapture(e.pointerId)
    pan.current = { sx: e.clientX, sy: e.clientY, bx: view.x, by: view.y }
  }
  const movePan = (e: React.PointerEvent) => {
    const p = pan.current
    if (!p) return
    if (p.node) {
      const pos = toSvg(e.clientX, e.clientY)
      setNodePos((prev) => ({ ...prev, [p.node!]: { x: pos.x, y: pos.y } }))
    } else {
      setView((v) => ({ ...v, x: p.bx + (e.clientX - p.sx), y: p.by + (e.clientY - p.sy) }))
    }
  }
  const endPan = (e: React.PointerEvent) => {
    pan.current = null
    try { e.currentTarget.releasePointerCapture(e.pointerId) } catch { /* noop */ }
  }
  const onWheel = (e: React.WheelEvent) => {
    const factor = e.deltaY < 0 ? 1.15 : 0.87
    setView((v) => ({ ...v, zoom: Math.min(3, Math.max(0.5, v.zoom * factor)) }))
  }

  const is3d = dim === '3d'
  const maxBytes = Math.max(...topo.edges.map((e) => e.bytes), 1)
  const maxConvs = Math.max(...renderNodes.map((n) => n.conversations), 1)
  return (
    <div className="topo-wrap">
      <div className="pane-title">
        主机拓扑 ({topo.nodes.length} 主机 · {topo.edges.length} 边)
        <span className="seg topo-dim">
          <button className={!is3d ? 'on' : ''} onClick={() => setDim('2d')}>2D</button>
          <button className={is3d ? 'on' : ''} onClick={() => setDim('3d')}>3D</button>
        </span>
      </div>
      {is3d ? (
        <Topology3D topo={topo} onSelectConversation={select} />
      ) : (
        <svg
          ref={svgRef}
          viewBox={`0 0 ${TOPO_W} ${TOPO_H}`}
          className="topo-svg"
          onPointerDown={startPan}
          onPointerMove={movePan}
          onPointerUp={endPan}
          onPointerCancel={endPan}
          onWheel={onWheel}
        >
          <g transform={`translate(${view.x} ${view.y}) scale(${view.zoom})`}>
            {topo.edges.map((e) => {
              const a = findNode(e.from)
              const b = findNode(e.to)
              if (!a || !b) return null
              return (
                <line
                  key={e.from + e.to}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
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
              )
            })}
            {renderNodes.map((n) => (
              <g
                key={n.id}
                className="topo-node"
                style={{ cursor: 'grab' }}
                onPointerDown={(ev) => {
                  ev.stopPropagation() // 空白平移与节点拖拽区分
                  if (typeof ev.currentTarget.setPointerCapture === 'function') ev.currentTarget.setPointerCapture(ev.pointerId)
                  pan.current = { sx: ev.clientX, sy: ev.clientY, bx: view.x, by: view.y, node: n.id }
                }}
              >
                <circle
                  r={6 + (n.conversations / maxConvs) * 9}
                  fill={n.issues ? '#fff7ed' : '#eff6ff'}
                  stroke={n.issues ? '#ea580c' : '#3b82f6'}
                  strokeWidth={2}
                />
                <text
                  y={-(6 + (n.conversations / maxConvs) * 9) - 5}
                  textAnchor="middle"
                  fontSize={10}
                  fill="#334155"
                  className="topo-label"
                >
                  {n.host}
                </text>
              </g>
            ))}
          </g>
        </svg>
      )}
      <div className="topo-hint">
        {is3d ? '拖拽旋转 · 滚轮缩放 · 节点大小 = 会话数;橙色 = 含异常' : '拖拽平移 · 滚轮缩放 · 拖动节点布局 · 点击边查看会话;橙色虚线 = 含异常'}
      </div>
    </div>
  )
}