import { useMemo, useRef, useState, type RefObject } from 'react'
import { layoutSequence, CLIENT_X, SERVER_X, HEADER_H, type LayoutMessage } from './layout'
import { displayHost } from '../model/types'
import { protocolColor } from '../model/protocolColors'
import { formatEpoch } from './timeFormat'
import { segmentConversation } from '../aggregate/segmentConversation'
import type { Conversation } from '../model/types'

export type TimeMode = 'relative' | 'absolute'

function fmtMsgTime(m: LayoutMessage, mode: TimeMode): string {
  if (mode === 'absolute' && m.timeEpoch != null) return formatEpoch(m.timeEpoch)
  return m.time.toFixed(3)
}

const DIR_COLOR: Record<string, string> = { request: '#3b82f6', response: '#f97316', other: '#94a3b8' }

function dirLabel(d: string): string {
  return d === 'request' ? '请求' : d === 'response' ? '响应' : '其他'
}

interface Props {
  conv: Conversation | null
  style: 'A' | 'B'
  timeMode?: TimeMode
  highlight?: readonly number[]
  onSelect: (n: number) => void
  svgRef: RefObject<SVGSVGElement | null>
  zoom: number
}

export function SequenceDiagram({ conv, style, timeMode = 'relative', highlight, onSelect, svgRef, zoom }: Props) {
  const [hover, setHover] = useState<LayoutMessage | null>(null)
  // 长会话分段:当前段为空表示全部;切段后时序图只渲染该段报文
  const segments = useMemo(() => (conv ? segmentConversation(conv.packets) : []), [conv])
  const [segIdx, setSegIdx] = useState<number | null>(null)
  const convId = conv?.id
  const prevConvRef = useRef(convId)
  if (convId !== prevConvRef.current) {
    prevConvRef.current = convId
    setSegIdx(null) // 切换会话时回到「全部」
  }

  // 所有 hooks 必须在提前 return 之前声明(否则空态→有会话会触发
  // 「Rendered more hooks than during the previous render」白屏)
  const activePackets = conv ? (segIdx != null ? (segments[segIdx]?.packets ?? conv.packets) : conv.packets) : []
  // 大包抽稀:>2000 报文按步长降采样渲染(首尾保底),交互仍基于原始报文号
  const stride = activePackets.length > 2000 ? Math.ceil(activePackets.length / 2000) : 1
  const downsampled = useMemo(() => {
    if (stride === 1) return activePackets
    const sampled = activePackets.filter((_, i) => i % stride === 0)
    const last = activePackets[activePackets.length - 1]
    if (sampled[sampled.length - 1] !== last) sampled.push(last) // 保底:尾包必须可见
    return sampled
  }, [activePackets, stride])
  // 布局与大包提示只在会话/风格/分段/抽稀变化时重算:hover、zoom、选中等状态变化不再全量重排
  const layout = useMemo(
    () => layoutSequence(downsampled, style, conv?.client ?? '', conv?.server ?? ''),
    [downsampled, style, conv?.client, conv?.server],
  )
  const many = activePackets.length > 2000 // 标注按原始报文数(抽稀本身即提示)
  const protos = useMemo(() => [...new Set(downsampled.map((p) => p.proto))].sort(), [downsampled])

  if (!conv) {
    return <div className="empty">从左侧选择一个会话查看时序图</div>
  }

  return (
    <div className="seq-wrap" style={{ flex: 1, overflow: 'auto', position: 'relative', background: '#f8fafc', border: '1px solid #eef2f7', borderRadius: 8, padding: 8 }}>
      {conv.issues.length > 0 && (
        <div className="issue-banner">
          ⚠ {conv.issues.map((i) => i.message).join('；')}
        </div>
      )}
      <div className="seq-header">
        <span className="endpoint">{displayHost(conv.client)}</span>
        <span className="arrow">⇄</span>
        <span className="endpoint">{displayHost(conv.server)}</span>
        <span className="seq-sub">
          {conv.protocol} · {conv.packetCount} 包 · {fmt(conv.bytes)} · {conv.start.toFixed(2)}~{conv.end.toFixed(2)}s
        </span>
        <span className="seq-legend">
          {protos.map((p) => (
            <span key={p}>
              <i style={{ background: protocolColor(p) }} />
              {p}
            </span>
          ))}
          <span className="seq-legend-sep" />
          <span>
            <i style={{ background: '#3b82f6' }} />
            请求
          </span>
          <span>
            <i style={{ background: '#f97316' }} />
            响应
          </span>
        </span>
        {many && (
          <span className="many-warn">
            报文较多:已抽稀显示 {downsampled.length}/{activePackets.length} 条(步长 {stride}),建议分段查看
          </span>
        )}
        {segments.length > 1 && (
          <span className="seg-nav">
            <button type="button" className={segIdx == null ? 'on' : ''} onClick={() => setSegIdx(null)}>
              全部
            </button>
            {segments.map((sg) => (
              <button
                key={sg.index}
                type="button"
                className={segIdx === sg.index ? 'on' : ''}
                title={`${sg.start.toFixed(2)}~${sg.end.toFixed(2)}s · ${sg.packetCount} 包`}
                onClick={() => setSegIdx(sg.index)}
              >
                {sg.index + 1}段
              </button>
            ))}
          </span>
        )}
      </div>
      {/* 盒尺寸随 zoom 同步放大:滚动容器按盒子尺寸计算,否则放大后图的下半部永远滚不到 */}
      <svg
        ref={svgRef}
        width={layout.width * zoom}
        height={layout.height * zoom}
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        style={{ display: 'block', font: '11px system-ui, sans-serif' }}
      >
        {/* lifelines + endpoint labels(顶部留白区) */}
        <line x1={CLIENT_X} y1={10} x2={CLIENT_X} y2={layout.height - 8} stroke="#cbd5e1" strokeDasharray="4 4" />
        <line x1={SERVER_X} y1={10} x2={SERVER_X} y2={layout.height - 8} stroke="#cbd5e1" strokeDasharray="4 4" />
        <text x={CLIENT_X} y={HEADER_H - 24} textAnchor="middle" fill="#1d4ed8" fontWeight="bold">
          {conv.client}
        </text>
        <text x={SERVER_X} y={HEADER_H - 24} textAnchor="middle" fill="#c2410c" fontWeight="bold">
          {conv.server}
        </text>
        <text x={CLIENT_X} y={HEADER_H - 10} textAnchor="middle" fill="#94a3b8" fontSize={9}>
          {conv.packetCount} 包 · {fmt(conv.bytes)}
        </text>

        {layout.messages.map((m, i) => {
          const retrans = m.analysis?.some((a) => a === 'retransmission' || a === 'fast-retransmission')
          const ooo = m.analysis?.includes('out-of-order')
          const dupAck = m.analysis?.includes('duplicate-ack')
          const lostSeg = m.analysis?.includes('lost-segment')
          const line = retrans || lostSeg ? '#ea580c' : protocolColor(m.proto)
          const dir = DIR_COLOR[m.direction]
          // 跨会话残留防护:旧会话的 hover 对象引用不在当前布局数组中则视为无效
          const isHover = hover != null && layout.messages.some((mm) => mm === hover)
          const isHit = highlight?.includes(m.id) ?? false
          return (
            <g
              key={`${style}-${m.id}`}
              className={isHover ? 'msg hover' : isHit ? 'msg hl' : 'msg'}
              style={{ cursor: 'pointer', animationDelay: `${Math.min(i * 22, 300)}ms` }}
              onClick={() => onSelect(m.id)}
              onMouseEnter={() => setHover(m)}
              onMouseLeave={() => setHover(null)}
            >
              <line
                className="arr"
                x1={m.x1}
                y1={m.y1}
                x2={m.x2}
                y2={m.y2}
                stroke={line}
                strokeWidth={isHover || isHit ? 2.6 : 1.6}
                strokeDasharray={retrans || ooo || lostSeg ? '5,3' : undefined}
                markerEnd={`url(#arr-${style})`}
              />
              {(retrans || ooo || dupAck || lostSeg) && (
                <text x={(m.x1 + m.x2) / 2} y={Math.min(m.y1, m.y2) - 14} textAnchor="middle" fontSize={9} fill={retrans || lostSeg ? '#ea580c' : '#0891b2'} fontWeight="bold">
                  {retrans ? '↻重传' : ooo ? '⇄乱序' : lostSeg ? '✕丢段' : '重复ACK'}
                </text>
              )}
              <circle cx={m.fromLeft ? CLIENT_X : SERVER_X} cy={m.y1 - 6} r={isHover ? 8 : 7} fill={dir} stroke="#fff" strokeWidth={1.5} className="dir-dot">
                <title>{dirLabel(m.direction)}</title>
              </circle>
              <text x={m.fromLeft ? CLIENT_X : SERVER_X} y={m.y1 - 3} textAnchor="middle" fill="#fff" fontSize={8} fontWeight="bold">
                {m.id}
              </text>
              <text x={6} y={m.y1 + 3} fill="#64748b" fontSize={9}>
                {fmtMsgTime(m, timeMode)}
              </text>
              <text className="msg-label" x={(m.x1 + m.x2) / 2} y={Math.min(m.y1, m.y2) - 4} textAnchor="middle" fill={line} fontSize={10}>
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
          #{hover.id} · {dirLabel(hover.direction)} · {hover.info} · {hover.len}B · {fmtMsgTime(hover, timeMode)}s
        </div>
      )}
    </div>
  )
}

function fmt(b: number): string {
  return b >= 1024 ? `${(b / 1024).toFixed(1)}KB` : `${b}B`
}
