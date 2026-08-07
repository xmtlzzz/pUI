import { useApp, selectFiltered, selectSelected } from '../state/appStore'

const PROTO_COLOR: Record<string, string> = {
  http: '#dcfce7 #15803d',
  https: '#f3e8ff #7c3aed',
  tls: '#f3e8ff #7c3aed',
  dns: '#dbeafe #1d4ed8',
  icmp: '#ffedd5 #c2410c',
  arp: '#f1f5f9 #475569',
  tcp: '#e0f2fe #0369a1',
  udp: '#ccfbf1 #0f766e',
}

function color(proto: string): [string, string] {
  const c = PROTO_COLOR[proto]
  return c ? (c.split(' ') as [string, string]) : ['#f8fafc', '#64748b']
}

export function ConversationList() {
  const filtered = useApp((s) => selectFiltered(s))
  const selected = useApp((s) => selectSelected(s))
  const select = useApp((s) => s.select)
  const hasData = useApp((s) => s.conversations.length > 0)

  if (!filtered.length) {
    return (
      <>
        <div className="pane-title">会话列表</div>
        <div className="empty">{hasData ? '当前筛选无结果,请放宽条件' : '打开文件后显示会话列表'}</div>
      </>
    )
  }

  return (
    <>
      <div className="pane-title">会话列表 ({filtered.length})</div>
      <table className="list">
        <thead>
          <tr>
            <th>客户端</th>
            <th>服务端</th>
            <th>协议</th>
            <th>包</th>
            <th>字节</th>
            <th>时长</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((c) => {
            const [bg, fg] = color(c.protocol)
            return (
              <tr key={c.id} className={selected?.id === c.id ? 'sel' : ''} onClick={() => select(c.id)}>
                <td title={c.client}>{c.client}</td>
                <td title={c.server}>{c.server}</td>
                <td>
                  <span className="badge" style={{ background: bg, color: fg }}>
                    {c.protocol}
                  </span>
                </td>
                <td>{c.packetCount}</td>
                <td>{fmtBytes(c.bytes)}</td>
                <td>{c.duration.toFixed(2)}s</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </>
  )
}

function fmtBytes(b: number): string {
  return b >= 1024 ? `${(b / 1024).toFixed(1)}KB` : `${b}B`
}
