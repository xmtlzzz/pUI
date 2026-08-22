import { useMemo, useState } from 'react'
import { useApp, selectSelected } from '../state/appStore'
import { protocolStyle } from '../model/protocolColors'
import { sortConversations, type SortKey } from './sortConversations'
import { searchConversations } from '../search/searchPackets'

/** 列表渲染上限:数万会话时全量渲染会让 DOM 爆炸,超限截断并提示用筛选缩小范围 */
const LIST_TRUNCATE = 1000
/** 虚拟化:固定行高 + 视口高度,只渲染可见窗口(±缓冲),滚动可达全部行 */
const ROW_H = 28
const VIEW_H = 600
const ROW_BUFFER = 10

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
  const selected = useApp((s) => selectSelected(s))
  const select = useApp((s) => s.select)
  const hasData = useApp((s) => s.conversations.length > 0)
  const sortKey = useApp((s) => s.sortKey)
  const sortDir = useApp((s) => s.sortDir)
  const setSort = useApp((s) => s.setSort)
  const searchQuery = useApp((s) => s.searchQuery)
  const setSearchQuery = useApp((s) => s.setSearchQuery)
  const setHighlight = useApp((s) => s.setHighlight)
  const [scrollTop, setScrollTop] = useState(0)
  const truncated = filtered.length > LIST_TRUNCATE
  // 搜索:命中会话+报文号;高亮联动在行点击时设置
  const searchHits = useMemo(() => searchConversations(filtered, searchQuery), [filtered, searchQuery])
  const searchActive = searchQuery.trim().length > 0
  const hitMap = useMemo(() => new Map(searchHits.map((m) => [m.convId, m.numbers])), [searchHits])
  const baseList = searchActive ? filtered.filter((c) => hitMap.has(c.id)) : filtered
  const scoped = truncated ? baseList.slice(0, LIST_TRUNCATE) : baseList
  const visible = useMemo(
    () => sortConversations(scoped, sortKey, sortDir),
    [scoped, sortKey, sortDir],
  )
  // 窗口化:scrollTop → 可见行区间(±缓冲);列表缩短(搜索/截断)时 clamp 残留滚动位置
  const total = visible.length
  const safeTop = Math.min(scrollTop, Math.max(0, (total - 1) * ROW_H))
  const start = Math.max(0, Math.floor(safeTop / ROW_H) - ROW_BUFFER)
  const end = Math.min(total, Math.ceil((safeTop + VIEW_H) / ROW_H) + ROW_BUFFER)
  const windowRows = visible.slice(start, end)

  if (!filtered.length) {
    return (
      <>
        <div className="pane-title">会话列表</div>
        <div className="empty">{hasData ? '当前筛选无结果,请放宽条件' : '打开文件后显示会话列表'}</div>
      </>
    )
  }

  if (searchActive && !visible.length) {
    return (
      <>
        <div className="pane-title">会话列表 ({filtered.length})</div>
        <SearchBox query={searchQuery} setQuery={setSearchQuery} />
        <div className="empty">无匹配「{searchQuery.trim()}」的报文,请调整关键词</div>
      </>
    )
  }

  return (
    <>
      <div className="pane-title">会话列表 ({searchActive ? visible.length : filtered.length})</div>
      <SearchBox query={searchQuery} setQuery={setSearchQuery} />
      {truncated && <div className="truncate-hint">已显示前 {LIST_TRUNCATE} 个会话(共 {filtered.length} 个),请使用筛选缩小范围</div>}
      <div className="cl-head">
        <span className="col-issue" aria-label="状态" />
        {COLUMNS.map((col) => (
          <span
            key={col.key}
            className={sortKey === col.key ? 'sorted' : ''}
            onClick={() => setSort(col.key)}
            title={col.key === 'start' ? '按开始时间排序' : `按${col.label}排序`}
          >
            {col.label}
            {sortKey === col.key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''}
          </span>
        ))}
        {searchActive && <span className="hit-col">命中</span>}
      </div>
      <div className="cl-scroll" onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
        {/* 撑高占位:滚动条按总量计算,行绝对定位 */}
        <div className="cl-body" style={{ height: total * ROW_H, position: 'relative' }}>
          {windowRows.map((c, i) => {
            const idx = start + i
            const st = protocolStyle(c.protocol)
            const hasIssue = c.issues.length > 0
            return (
              <div
                key={c.id}
                data-idx={idx}
                className={`cl-row ${selected?.id === c.id ? 'sel' : ''}${hasIssue ? ' has-issue' : ''}`}
                style={{ top: idx * ROW_H, height: ROW_H, animationDelay: `${Math.min(idx * 28, 300)}ms` }}
                onClick={() => {
                  select(c.id)
                  if (searchActive) setHighlight(hitMap.get(c.id) ?? []) // 定位:高亮命中的报文
                }}
              >
                <span className="col-issue">
                  {hasIssue && (
                    <span className="issue-mark" title={c.issues.map((x) => x.message).join('\n')}>
                      ⚠
                    </span>
                  )}
                </span>
                <span className="cl-cell" title={c.client}>{c.client}</span>
                <span className="cl-cell" title={c.server}>{c.server}</span>
                <span>
                  <span className="badge" style={{ background: st.bg, color: st.fg }}>
                    {c.protocol}
                  </span>
                </span>
                <span>{c.packetCount}</span>
                <span>{fmtBytes(c.bytes)}</span>
                <span>{c.duration.toFixed(2)}s</span>
                <span className="time-col">{c.start.toFixed(2)}s</span>
                {searchActive && <span className="hit-col">{hitMap.get(c.id)?.length ?? 0} 命中</span>}
              </div>
            )
          })}
        </div>
      </div>
    </>
  )
}

function fmtBytes(b: number): string {
  return b >= 1024 ? `${(b / 1024).toFixed(1)}KB` : `${b}B`
}

function SearchBox({ query, setQuery }: { query: string; setQuery: (q: string) => void }) {
  return (
    <div className="search-box">
      <input
        type="search"
        value={query}
        placeholder="搜索报文(协议/地址/端口/URL/DNS)…"
        aria-label="搜索报文"
        onChange={(e) => setQuery(e.target.value)}
      />
      {query && (
        <button type="button" className="search-clear" onClick={() => setQuery('')} aria-label="清除搜索">
          ✕
        </button>
      )}
    </div>
  )
}
