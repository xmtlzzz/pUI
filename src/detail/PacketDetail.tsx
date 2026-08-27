import { useEffect, useState, type MouseEvent } from 'react'
import { useApp, selectSelectedPacket } from '../state/appStore'
import { buildPacketTree, type DetailNode } from './packetTree'

export function PacketDetail({ onViewTcpEvents }: { onViewTcpEvents?: () => void } = {}) {
  const packet = useApp((s) => selectSelectedPacket(s))
  const fetchHexFor = useApp((s) => s.fetchHexFor)
  const getHex = useApp((s) => s.getHex)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(false)

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

  if (!packet) return <div className="empty">点击时序图中的报文查看详情</div>

  const hex = getHex(packet.number)

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
      <Tree nodes={buildPacketTree(packet)} />
      {busy && <div style={{ color: '#94a3b8' }}>加载 hex…</div>}
      {err && <div style={{ color: '#b91c1c' }}>hex 不可用</div>}
      {hex && <pre className="detail-hex">{hex}</pre>}
    </div>
  )
}

/** 分层树渲染:帧 → L2 → L3 → L4 → 应用层,每组可折叠 */
function Tree({ nodes, depth = 0 }: { nodes: DetailNode[]; depth?: number }) {
  return (
    <div style={{ marginLeft: depth * 10 }}>
      {nodes.map((n) =>
        n.children ? (
          <details key={n.key} open={depth === 0} className="detail-group">
            <summary className="detail-group-title">{n.label}</summary>
            <Tree nodes={n.children} depth={depth + 1} />
          </details>
        ) : (
          <div key={n.key} className="detail-kv">
            <span className="detail-k">{n.label}</span>
            <span className="detail-v">{n.value ?? '—'}</span>
          </div>
        ),
      )}
    </div>
  )
}
