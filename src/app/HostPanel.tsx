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
  return (
    <>
      <div className="pane-title">主机视角 ({hosts.length})</div>
      <table className="list">
        <thead>
          <tr>
            <th>主机</th>
            <th>会话</th>
            <th>字节</th>
            <th>客</th>
            <th>服</th>
            <th>异常</th>
          </tr>
        </thead>
        <tbody>
          {hosts.slice(0, 100).map((h) => (
            <tr key={h.host} title={`${h.protocols.join(', ')}`}>
              <td>{h.host}</td>
              <td>{h.conversations}</td>
              <td>{fmtBytes(h.bytes)}</td>
              <td>{h.asClient}</td>
              <td>{h.asServer}</td>
              <td>{h.issues ? `⚠ ${h.issues}` : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {hosts.length > 100 && <div className="truncate-hint">已显示字节量 Top 100 主机</div>}
    </>
  )
}

function fmtBytes(b: number): string {
  if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)}MB`
  if (b >= 1024) return `${(b / 1024).toFixed(1)}KB`
  return `${b}B`
}
