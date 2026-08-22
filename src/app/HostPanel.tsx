import { useMemo } from 'react'
import { useApp } from '../state/appStore'
import { aggregateHosts } from '../stats/hostStats'

/** 左侧「主机」面板:谁和谁通信最多、哪些主机异常(Endpoint 视角) */
export function HostPanel() {
  const conversations = useApp((s) => s.conversations)
  const hosts = useMemo(() => aggregateHosts(conversations), [conversations])

  if (!hosts.length) {
    return <div className="empty">打开文件后显示主机统计</div>
  }
  const maxConversations = Math.max(...hosts.map((h) => h.conversations), 1)
  return (
    <>
      <div className="pane-title">主机视角 ({hosts.length})</div>
      <div className="hp-scroll">
        <div className="hp-head">
          <span>主机 Host</span>
          <span>会话</span>
          <span>字节</span>
          <span title="该主机作为发起方(客户端)的会话数">Client</span>
          <span title="该主机作为服务方的会话数">Server</span>
          <span title="涉及会话的异常总数">Error</span>
        </div>
        {hosts.slice(0, 100).map((h) => (
          <div key={h.host} className="hp-row" title={h.protocols.join(', ')}>
            <span className="hp-host">
              <i className="hp-dot" style={{ transform: `scale(${Math.max(0.6, 0.8 + (h.conversations / maxConversations) * 0.5)})` }} />
              {h.host}
            </span>
            <span>{h.conversations}</span>
            <span className="hp-num">{fmtBytes(h.bytes)}</span>
            <span className={h.asClient ? 'hp-role client' : 'hp-role'}>{h.asClient || '—'}</span>
            <span className={h.asServer ? 'hp-role server' : 'hp-role'}>{h.asServer || '—'}</span>
            <span className={h.issues ? 'hp-err' : 'hp-role'}>{h.issues ? `⚠ ${h.issues}` : '—'}</span>
          </div>
        ))}
      </div>
      {hosts.length > 100 && <div className="truncate-hint">已显示字节量 Top 100 主机</div>}
    </>
  )
}

function fmtBytes(b: number): string {
  if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)}MB`
  if (b >= 1024) return `${(b / 1024).toFixed(1)}KB`
  return `${b}B`
}