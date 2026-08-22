import { useMemo } from 'react'
import { useApp } from '../state/appStore'
import { deriveSummary } from '../stats/summaryStats'
import { protocolColor } from '../model/protocolColors'

/** 左侧「摘要」面板:协议的体检报告(安全初看/教学场景) */
export function SummaryPanel() {
  const conversations = useApp((s) => s.conversations)
  const summary = useMemo(() => deriveSummary(conversations), [conversations])

  if (!summary.conversationCount) {
    return <div className="empty">打开文件后显示分析摘要</div>
  }
  const maxProto = Math.max(...summary.protocolCounts.map((p) => p.count), 1)
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
    </>
  )
}

function fmtBytes(b: number): string {
  if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)}MB`
  if (b >= 1024) return `${(b / 1024).toFixed(1)}KB`
  return `${b}B`
}
