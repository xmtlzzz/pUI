import { useApp, selectSelected } from '../state/appStore'
import { protocolStyle } from '../model/protocolColors'

export function ConversationList() {
  const filtered = useApp((s) => s.filtered)
  const filter = useApp((s) => s.filter)
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
        {/* 筛选变化时重挂载 tbody,行逐条滑入,让刷新可见 */}
        <tbody key={JSON.stringify(filter)}>
          {filtered.map((c, i) => {
            const st = protocolStyle(c.protocol)
            return (
              <tr key={c.id} className={`row-in${selected?.id === c.id ? ' sel' : ''}`} style={{ animationDelay: `${i * 28}ms` }} onClick={() => select(c.id)}>
                <td title={c.client}>{c.client}</td>
                <td title={c.server}>{c.server}</td>
                <td>
                  <span className="badge" style={{ background: st.bg, color: st.fg }}>
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
