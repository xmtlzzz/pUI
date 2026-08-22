import { useMemo } from 'react'
import { useApp } from '../state/appStore'
import { deriveSummary } from '../stats/summaryStats'
import { buildHistogram } from '../stats/histogram'
import { protocolColor } from '../model/protocolColors'

/** 左侧「摘要」面板:协议的体检报告(安全初看/教学场景) */
export function SummaryPanel() {
  const conversations = useApp((s) => s.conversations)
  const packets = useApp((s) => s.packets)
  const timeRange = useApp((s) => s.timeRange)
  const setTimeRange = useApp((s) => s.setTimeRange)
  const summary = useMemo(() => deriveSummary(conversations), [conversations])
  const buckets = useMemo(() => buildHistogram(packets, 24), [packets])

  if (!summary.conversationCount) {
    return <div className="empty">打开文件后显示分析摘要</div>
  }
  const maxProto = Math.max(...summary.protocolCounts.map((p) => p.count), 1)
  const maxBucket = Math.max(...buckets.map((b) => b.count), 1)
  return (
    <>
      <div className="pane-title">分析摘要</div>
      <div className="summary-grid">
        <span>会话 <b>{summary.conversationCount}</b></span>
        <span>报文 <b>{summary.packetCount}</b></span>
        <span>字节 <b>{fmtBytes(summary.totalBytes)}</b></span>
        <span>时长 <b>{summary.duration.toFixed(2)}s</b></span>
        <span>异常会话 <b>{summary.issueConversations}</b></span>
      </div>
      <div className="sub-title">协议分布</div>
      {summary.protocolCounts.map((p) => (
        <div key={p.protocol} className="bar-row">
          <span className="bar-label">{p.protocol}</span>
          <div className="bar">
            <div className="bar-fill" style={{ width: `${(p.count / maxProto) * 100}%`, background: protocolColor(p.protocol) }} />
          </div>
          <span className="bar-val">{p.count}</span>
        </div>
      ))}
      {summary.issueTypeCounts.length > 0 && (
        <>
          <div className="sub-title">异常类型</div>
          <div className="issue-line">{summary.issueTypeCounts.map((i) => `${i.type}×${i.count}`).join(' · ')}</div>
        </>
      )}
      <div className="sub-title">Top 主机</div>
      <div className="issue-line">{summary.topHosts.map((h) => `${h.host} ${fmtBytes(h.bytes)}`).join(' · ')}</div>
      <div className="sub-title">时间分布(点击桶下钻)</div>
      <div className="hist">
        {buckets.map((b) => {
          const active = timeRange != null && b.start >= timeRange.start && b.end <= timeRange.end
          return (
            <button
              key={b.index}
              type="button"
              className={`hist-bar${active ? ' on' : ''}`}
              style={{ height: `${Math.max(3, (b.count / maxBucket) * 48)}px` }}
              title={`${b.start.toFixed(2)}~${b.end.toFixed(2)}s · ${b.count} 报文`}
              onClick={() => setTimeRange(timeRange != null && active ? null : { start: b.start, end: b.end })}
            />
          )
        })}
      </div>
      {timeRange && (
        <div className="range-line">
          已下钻 {timeRange.start.toFixed(2)}~{timeRange.end.toFixed(2)}s · 会话 {summary.conversationCount}
          <button type="button" className="range-clear" onClick={() => setTimeRange(null)}>
            清除区间
          </button>
        </div>
      )}
    </>
  )
}

function fmtBytes(b: number): string {
  if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)}MB`
  if (b >= 1024) return `${(b / 1024).toFixed(1)}KB`
  return `${b}B`
}
