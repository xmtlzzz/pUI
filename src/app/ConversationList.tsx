import { useMemo } from 'react'
import { useApp, selectSelected } from '../state/appStore'
import { protocolStyle } from '../model/protocolColors'
import { sortConversations, type SortKey } from './sortConversations'

/** 列表渲染上限:数万会话时全量渲染会让 DOM 爆炸,超限截断并提示用筛选缩小范围 */
const LIST_TRUNCATE = 1000

const COLUMNS: Array<{ key: SortKey; label: string }> = [
  { key: 'client', label: '客户端' },
  { key: 'server', label: '服务端' },
  { key: 'protocol', label: '协议' },
  { key: 'packetCount', label: '包' },
  { key: 'bytes', label: '字节' },
  { key: 'duration', label: '时长' },
  { key: 'start', label: '开始' },
]

export function ConversationList() {
  const filtered = useApp((s) => s.filtered)
  const filter = useApp((s) => s.filter)
  const selected = useApp((s) => selectSelected(s))
  const select = useApp((s) => s.select)
  const hasData = useApp((s) => s.conversations.length > 0)
  const sortKey = useApp((s) => s.sortKey)
  const sortDir = useApp((s) => s.sortDir)
  const setSort = useApp((s) => s.setSort)
  const truncated = filtered.length > LIST_TRUNCATE
  const visible = useMemo(
    () => sortConversations(truncated ? filtered.slice(0, LIST_TRUNCATE) : filtered, sortKey, sortDir),
    [filtered, sortKey, sortDir, truncated],
  )

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
      {truncated && <div className="truncate-hint">已显示前 {LIST_TRUNCATE} 个会话(共 {filtered.length} 个),请使用筛选缩小范围</div>}
      <table className="list">
        <thead>
          <tr>
            <th className="col-issue" aria-label="状态"></th>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className={sortKey === col.key ? 'sorted' : ''}
                aria-sort={sortKey === col.key ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
                onClick={() => setSort(col.key)}
                title={col.key === 'start' ? '按开始时间排序' : `按${col.label}排序`}
              >
                {col.label}
                {sortKey === col.key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''}
              </th>
            ))}
          </tr>
        </thead>
        {/* 筛选变化时重挂载 tbody,行逐条滑入,让刷新可见 */}
        <tbody key={`${JSON.stringify(filter)}-${sortKey}-${sortDir}`}>
          {visible.map((c, i) => {
            const st = protocolStyle(c.protocol)
            const hasIssue = c.issues.length > 0
            return (
              <tr
                key={c.id}
                className={`row-in${selected?.id === c.id ? ' sel' : ''}${hasIssue ? ' has-issue' : ''}`}
                style={{ animationDelay: `${Math.min(i * 28, 300)}ms` }}
                onClick={() => select(c.id)}
              >
                <td className="col-issue">
                  {hasIssue && (
                    <span className="issue-mark" title={c.issues.map((x) => x.message).join('\n')}>
                      ⚠
                    </span>
                  )}
                </td>
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
                <td className="time-col">{c.start.toFixed(2)}s</td>
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
