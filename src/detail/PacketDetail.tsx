import { useEffect, useMemo, useRef, useState, type MouseEvent } from 'react'
import { useApp, selectSelectedPacket } from '../state/appStore'
import { buildPacketTree, type DetailNode, type ByteRange } from './packetTree'
import { parseHexLayout, rangeToLines } from './hexLayout'
import { EmotionBallLoader } from '../app/EmotionBallLoader'

/** hex 数据行高(px),滚动定位时乘行下标得 scrollTop */
const HEX_LINE_H = 16

/** 扁平化节点:pathKey 唯一化(如 l3.src / app.http),叶子字段继承所在层的字节区域 */
interface FlatNode {
  key: string
  label: string
  value?: string
  range?: ByteRange
  hasChildren: boolean
}

function flatten(nodes: DetailNode[]): FlatNode[] {
  const out: FlatNode[] = []
  const walk = (list: DetailNode[], prefix?: string, parentRange?: ByteRange): void => {
    for (const n of list) {
      const pathKey = prefix ? `${prefix}.${n.key}` : n.key
      const range = n.range ?? parentRange
      out.push({ key: pathKey, label: n.label, value: n.value, range, hasChildren: !!n.children })
      if (n.children) walk(n.children, pathKey, range)
    }
  }
  walk(nodes)
  return out
}

export function PacketDetail({ onViewTcpEvents }: { onViewTcpEvents?: () => void } = {}) {
  const packet = useApp((s) => selectSelectedPacket(s))
  const fetchHexFor = useApp((s) => s.fetchHexFor)
  const getHex = useApp((s) => s.getHex)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(false)
  /** 点击选中的节点(pathKey);hex 高亮优先展示悬停,其次点击 */
  const [selKey, setSelKey] = useState<string | null>(null)
  const [hoverKey, setHoverKey] = useState<string | null>(null)
  const hexRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    setErr(false)
    if (!packet) return
    setBusy(true)
    let active = true
    fetchHexFor(packet.number)
      .catch(() => {
        if (active) setErr(true)
      })
      .finally(() => {
        if (active) setBusy(false)
      })
    return () => {
      active = false // 切换报文后,丢弃陈旧请求的 UI 更新
    }
  }, [packet?.number]) // eslint-disable-line react-hooks/exhaustive-deps

  // 切换报文:清空残留的联动状态(旧报文的区域对不上新 hex)
  useEffect(() => {
    setSelKey(null)
    setHoverKey(null)
  }, [packet?.number]) // eslint-disable-line react-hooks/exhaustive-deps

  const hex = packet ? getHex(packet.number) : null
  const hexLines = useMemo(() => (hex ? parseHexLayout(hex).map((l) => l.text) : []), [hex])
  const nodes = useMemo(() => (packet ? flatten(buildPacketTree(packet)) : []), [packet])

  const activeNode = nodes.find((n) => n.key === (hoverKey ?? selKey)) ?? null
  const activeSpans = useMemo(() => {
    if (!hex || !activeNode?.range) return []
    return rangeToLines(hex, activeNode.range.start, activeNode.range.end)
  }, [hex, activeNode])
  const activeLines = useMemo(() => new Set(activeSpans.map((r) => r.line)), [activeSpans])
  const firstLine = activeSpans.length ? activeSpans[0].line : -1

  // 点击字段后滚动 hex 到高亮首行(悬停只高亮不滚动,避免抖动)
  useEffect(() => {
    if (firstLine < 0) return
    const pre = hexRef.current
    if (pre) pre.scrollTop = Math.max(0, firstLine * HEX_LINE_H)
  }, [firstLine, selKey]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!packet) return <div className="empty">点击时序图中的报文查看详情</div>

  const handleHover = (key: string | null): void => setHoverKey(key)
  const handleClick = (key: string): void => setSelKey((cur) => (cur === key ? null : key))

  return (
    <div className="detail-bar">
      {/* TCP 报文附「查看事件上下文」入口(计划 M4):报文详情 ↔ 故障分析双向可达 */}
      <div className="detail-title-row">
        <div className="detail-title">报文详情 · #{packet.number}</div>
        {onViewTcpEvents && packet.transport === 'tcp' && (
          <button
            type="button"
            className="btn sm detail-evbtn"
            data-testid="pd-view-events"
            onClick={(e: MouseEvent) => {
              e.stopPropagation()
              onViewTcpEvents()
            }}
          >
            查看事件上下文 →
          </button>
        )}
      </div>
      <Tree nodes={buildPacketTree(packet)} onHover={handleHover} onClick={handleClick} />
      {busy && (
        <div className="hex-loading" style={{ color: '#94a3b8' }}>
          <EmotionBallLoader emotionId="40" tips="检索 hex…" size={40} />
        </div>
      )}
      {err && <div style={{ color: '#b91c1c' }}>hex 不可用</div>}
      {hex && (
        <>
          <div className="detail-hex-hint">提示:点击/悬停协议字段可在 hex 中定位字节区域</div>
          <div className="detail-hex" data-testid="detail-hex" ref={hexRef}>
            {hexLines.map((line, i) => (
              <div
                key={i}
                className={activeLines.has(i) ? 'detail-hex-line hl' : 'detail-hex-line'}
                data-testid={`detail-hex-line-${i}`}
                data-highlighted={activeLines.has(i) ? 'true' : undefined}
              >
                {line}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

/** 分层树渲染:帧 → L2 → L3 → L4 → 应用层,每组可折叠;节点可悬停/点击联动 hex */
function Tree({
  nodes,
  depth = 0,
  onHover,
  onClick,
  parentKey,
}: {
  nodes: DetailNode[]
  depth?: number
  onHover: (key: string | null) => void
  onClick: (key: string) => void
  parentKey?: string
}) {
  return (
    <div style={{ marginLeft: depth * 10 }}>
      {nodes.map((n) => {
        const pathKey = parentKey ? `${parentKey}.${n.key}` : n.key
        if (n.children) {
          return (
            <details key={n.key} open={depth === 0} className="detail-group">
              <summary
                className="detail-group-title"
                data-testid={`detail-title-${pathKey}`}
                onMouseEnter={() => onHover(pathKey)}
                onMouseLeave={() => onHover(null)}
                onClick={() => onClick(pathKey)}
              >
                {n.label}
              </summary>
              <Tree nodes={n.children} depth={depth + 1} onHover={onHover} onClick={onClick} parentKey={pathKey} />
            </details>
          )
        }
        return (
          <div
            key={n.key}
            className="detail-kv"
            data-testid={`detail-field-${pathKey}`}
            onMouseEnter={() => onHover(pathKey)}
            onMouseLeave={() => onHover(null)}
            onClick={() => onClick(pathKey)}
          >
            <span className="detail-k">{n.label}</span>
            <span className="detail-v">{n.value ?? '—'}</span>
          </div>
        )
      })}
    </div>
  )
}
