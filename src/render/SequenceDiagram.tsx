import { useState, type RefObject } from 'react'
import { layoutSequence, CLIENT_X, SERVER_X, type LayoutMessage } from './layout'
import type { Conversation } from '../model/types'

const PROTO_COLOR: Record<string, string> = {
  tcp: '#2563eb',
  http: '#16a34a',
  https: '#7c3aed',
  tls: '#7c3aed',
  dns: '#0891b2',
  udp: '#0d9488',
  icmp: '#ea580c',
  arp: '#64748b',
}
const DIR_COLOR: Record<string, string> = { request: '#3b82f6', response: '#f97316', other: '#94a3b8' }

function protoColor(proto: string): string {
  return PROTO_COLOR[proto] ?? '#6b7280'
}
function dirLabel(d: string): string {
  return d === 'request' ? '请求' : d === 'response' ? '响应' : '其他'
}

interface Props {
  conv: Conversation | null
  style: 'A' | 'B'
  onSelect: (n: number) => void
  svgRef: RefObject<SVGSVGElement | null>
  zoom: number
}

export function SequenceDiagram({ conv, style, onSelect, svgRef, zoom }: Props) {
  const [hover, setHover] = useState<LayoutMessage | null>(null)

  if (!conv) {
    return <div className="empty">从左侧选择一个会话查看时序图</div>
  }

  const layout = layoutSequence(conv.packets, style, conv.client, conv.server)
  const many = conv.packets.length > 2000

  return (
    <div className="seq-wrap" style={{ flex: 1, overflow: 'auto', position: 'relative', background: '#f8fafc', border: '1px solid #eef2f7', borderRadius: 8, padding: 8 }}>
      <div className="seq-header">
        <span className="endpoint">{conv.client.split(':')[0]}</span>
        <span className="arrow">⇄</span>
        <span className="endpoint">{conv.server.split(':')[0]}</span>
        <span className="seq-sub">
          {conv.protocol} · {conv.packetCount} 包 · {fmt(conv.bytes)} · {conv.start.toFixed(2)}~{conv.end.toFixed(2)}s
        </span>
        {many && <span className="many-warn">报文较多,建议风格 B / 缩放</span>}
      </div>
      <svg
        ref={svgRef}
        width={layout.width}
        height={layout.height}
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        style={{ display: 'block', font: '11px system-ui, sans-serif', transform: `scale(${zoom})`, transformOrigin: 'top left' }}
      >
        {/* lifelines + endpoint labels */}
        <line x1={CLIENT_X} y1={12} x2={CLIENT_X} y2={layout.height - 8} stroke="#cbd5e1" strokeDasharray="4 4" />
        <line x1={SERVER_X} y1={12} x2={SERVER_X} y2={layout.height - 8} stroke="#cbd5e1" strokeDasharray="4 4" />
        <text x={CLIENT_X} y={12} textAnchor="middle" fill="#1d4ed8" fontWeight="bold">
          {conv.client}
        </text>
        <text x={SERVER_X} y={12} textAnchor="middle" fill="#c2410c" fontWeight="bold">
          {conv.server}
        </text>
        <text x={CLIENT_X} y={24} textAnchor="middle" fill="#94a3b8" fontSize={9}>
          {conv.packetCount} 包 · {fmt(conv.bytes)}
        </text>

        {layout.messages.map((m, i) => {
          const line = protoColor(m.proto)
          const dir = DIR_COLOR[m.direction]
          return (
            <g
              key={`${style}-${m.id}`}
              className="msg"
              style={{ cursor: 'pointer', animationDelay: `${i * 22}ms` }}
              onClick={() => onSelect(m.id)}
              onMouseEnter={() => setHover(m)}
              onMouseLeave={() => setHover(null)}
            >
              <line x1={m.x1} y1={m.y1} x2={m.x2} y2={m.y2} stroke={line} strokeWidth={hover?.id === m.id ? 2.6 : 1.6} markerEnd={`url(#arr-${style})`} />
              <circle cx={m.fromLeft ? CLIENT_X : SERVER_X} cy={m.y1 - 6} r={7} fill={dir} stroke="#fff" strokeWidth={1.5}>
                <title>{dirLabel(m.direction)}</title>
              </circle>
              <text x={m.fromLeft ? CLIENT_X : SERVER_X} y={m.y1 - 3} textAnchor="middle" fill="#fff" fontSize={8} fontWeight="bold">
                {m.id}
              </text>
              <text x={6} y={m.y1 + 3} fill="#64748b" fontSize={9}>
                {m.time.toFixed(3)}
              </text>
              <text x={(m.x1 + m.x2) / 2} y={Math.min(m.y1, m.y2) - 4} textAnchor="middle" fill={line} fontSize={10}>
                {m.info} · {m.len}B
              </text>
            </g>
          )
        })}
        <defs>
          <marker id={`arr-${style}`} markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
            <path d="M0,0 L7,3 L0,6 z" fill="#475569" />
          </marker>
        </defs>
      </svg>
      {hover && (
        <div
          className="msg-tooltip"
          style={{
            position: 'absolute',
            left: (hover.x1 + hover.x2) / 2,
            top: Math.min(hover.y1, hover.y2) - 26,
            background: '#0f172a',
            color: '#e2e8f0',
            padding: '4px 8px',
            borderRadius: 6,
            fontSize: 11,
            pointerEvents: 'none',
            zIndex: 5,
          }}
        >
          #{hover.id} · {dirLabel(hover.direction)} · {hover.info} · {hover.len}B · {hover.time.toFixed(3)}s
        </div>
      )}
    </div>
  )
}

function fmt(b: number): string {
  return b >= 1024 ? `${(b / 1024).toFixed(1)}KB` : `${b}B`
}
