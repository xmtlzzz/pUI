import { useEffect, useState } from 'react'
import { useApp, selectSelectedPacket } from '../state/appStore'
import type { Packet } from '../model/types'

export function PacketDetail() {
  const packet = useApp((s) => selectSelectedPacket(s))
  const fetchHexFor = useApp((s) => s.fetchHexFor)
  const getHex = useApp((s) => s.getHex)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(false)

  useEffect(() => {
    setErr(false)
    if (!packet) return
    setBusy(true)
    fetchHexFor(packet.number)
      .catch(() => setErr(true))
      .finally(() => setBusy(false))
  }, [packet?.number]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!packet) return <div className="empty">点击时序图中的报文查看详情</div>

  const hex = getHex(packet.number)

  return (
    <div className="detail-bar">
      <div className="detail-title">报文详情 · #{packet.number}</div>
      <Row p={packet} />
      {busy && <div style={{ color: '#94a3b8' }}>加载 hex…</div>}
      {err && <div style={{ color: '#b91c1c' }}>hex 不可用</div>}
      {hex && <pre className="detail-hex">{hex}</pre>}
    </div>
  )
}

function Row({ p }: { p: Packet }) {
  const kv: Array<[string, string]> = [
    ['时间', `${p.time.toFixed(3)}s`],
    ['长度', `${p.len}B`],
    ['协议', p.proto],
    ['方向', p.direction === 'request' ? '请求' : p.direction === 'response' ? '响应' : '其他'],
    ['源', p.srcIp ? (p.srcPort != null ? `${p.srcIp}:${p.srcPort}` : p.srcIp) : (p.srcMac ?? '—')],
    ['目的', p.dstIp ? (p.dstPort != null ? `${p.dstIp}:${p.dstPort}` : p.dstIp) : (p.dstMac ?? '—')],
    ['L2', p.srcMac && p.dstMac ? `${p.srcMac} → ${p.dstMac}` : '—'],
    ['TCP', p.tcpFlags ? `flags=${p.tcpFlags} seq=${p.tcpSeq ?? '—'} ack=${p.tcpAck ?? '—'}` : '—'],
    ['HTTP', p.httpMethod ? `${p.httpMethod} ${p.httpUri ?? ''}` : p.httpCode ? `status ${p.httpCode}` : '—'],
    ['DNS', p.dnsQuery ?? '—'],
  ]
  return (
    <div style={{ marginBottom: 4 }}>
      {kv.map(([k, v]) => (
        <span key={k} style={{ marginRight: 12, color: '#475569' }}>
          <b style={{ color: '#94a3b8' }}>{k}</b> {v}
        </span>
      ))}
    </div>
  )
}
