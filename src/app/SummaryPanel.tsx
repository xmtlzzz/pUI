import { useMemo } from 'react'
import { useApp } from '../state/appStore'
import { deriveSummary } from '../stats/summaryStats'
import { buildHistogram } from '../stats/histogram'
import { deriveTcpStats } from '../stats/tcpStats'
import { tcpStatRows } from '../stats/tcpStatHints'
import { computeRttStats, MIN_RTT_SAMPLES } from '../stats/rttStats'
import { computeCaptureQuality } from '../stats/captureQuality'
import { computeWindowStats } from '../stats/windowStats'
import { computeHealthScore } from '../stats/healthScore'
import { protocolColor } from '../model/protocolColors'
import { displayHost } from '../model/types'

/** 下钻高亮上限:与 appStore 时序图高亮护栏同档,超出截断仅影响视觉定位 */
const HIGHLIGHT_LIMIT = 2000

/** 左侧「摘要」面板:协议的体检报告(安全初看/教学场景) */
export function SummaryPanel() {
  const conversations = useApp((s) => s.conversations)
  const packets = useApp((s) => s.packets)
  const timeRange = useApp((s) => s.timeRange)
  const setTimeRange = useApp((s) => s.setTimeRange)
  const selectedId = useApp((s) => s.selectedId)
  const setHighlight = useApp((s) => s.setHighlight)
  const summary = useMemo(() => deriveSummary(conversations), [conversations])
  const buckets = useMemo(() => buildHistogram(packets, 24), [packets])
  // TCP 异常统计:针对当前选中会话的全量报文(不受分段/抽稀影响),点击行高亮下钻
  const conv = useMemo(() => conversations.find((c) => c.id === selectedId) ?? null, [conversations, selectedId])
  const tcpRows = useMemo(
    () => (conv ? tcpStatRows(deriveTcpStats(conv.packets), conv.packets.length) : []),
    [conv],
  )
  // M5:选中会话的 RTT 近似与采集质量(样本不足/字段缺失时显式 unavailable)
  const rtt = useMemo(() => (conv ? computeRttStats(conv.packets) : null), [conv])
  const cq = useMemo(() => (conv ? computeCaptureQuality(conv.packets) : null), [conv])
  const ws = useMemo(() => (conv ? computeWindowStats(conv.packets) : null), [conv])
  const health = useMemo(() => (conv ? computeHealthScore(conv.packets) : null), [conv])

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
      {tcpRows.length > 0 ? (
        <>
          <div className="sub-title">TCP 异常统计({displayHost(conv!.client)} ⇄ {displayHost(conv!.server)})</div>
          <div className="tcp-stat">
            <div className="tcp-stat-head">
              <span>标记</span>
              <span className="num">数量</span>
              <span>先怎么理解</span>
            </div>
            {tcpRows.map((r) => (
              <button
                key={r.key}
                type="button"
                className="tcp-stat-row"
                title="点击在时序图中高亮该类报文"
                onClick={() => {
                  // 下钻:高亮该会话中带此类标签的报文(时序图紫色高亮 + 定位)
                  const nums = (conv?.packets ?? []).filter((p) => p.tcpAnalysis?.includes(r.key)).map((p) => p.number)
                  setHighlight(nums.length > HIGHLIGHT_LIMIT ? nums.slice(0, HIGHLIGHT_LIMIT) : nums)
                }}
              >
                <span className="mark">{r.label}</span>
                <span className="num">{r.count}</span>
                <span className="hint">{r.hint}</span>
              </button>
            ))}
          </div>
        </>
      ) : (
        conv && <div className="sub-title">TCP 异常统计:当前会话无重传/乱序等标记</div>
      )}
      {/* M5:RTT 近似与采集质量(样本不足/字段缺失显式 unavailable,不编造数字) */}
      {conv && health && (
        <div className="issue-line" data-testid="summary-health" title="透明健康分:仅用于筛选排序,不进入证据/导出;悬停查看扣分明细">
          健康分 <b style={{ color: (health.score ?? 0) >= 80 ? '#059669' : (health.score ?? 0) >= 50 ? '#d97706' : '#dc2626' }}>{health.score ?? '—'}</b>
          <span className="dim"> ({health.formula} · 仅筛选用)</span>
          {health.deductions.length > 0 && (
            <span> — {health.deductions.map((d) => `${d.reason}(-${d.points})`).join('; ')}</span>
          )}
        </div>
      )}
      {conv && rtt && cq && (
        <>
          <div className="sub-title">会话测量(选中会话 · 单观察点近似)</div>
          <div className="summary-grid" data-testid="summary-m5">
            <span title="数据段与其后首个反向 ACK 的间隔,含对端处理时延,非纯网络往返;重传按首次发送归属(Karn 近似)">
              RTT p50 <b>{rtt.available ? `${rtt.p50Ms}ms` : 'unavailable'}</b>
            </span>
            <span title={rtt.available ? undefined : `确认事件样本 ${rtt.samples} < ${MIN_RTT_SAMPLES},不足以给出分位数`}>
              RTT p90 <b>{rtt.available ? `${rtt.p90Ms}ms` : 'unavailable'}</b>
            </span>
            <span>RTT max <b>{rtt.available ? `${rtt.maxMs}ms` : '—'}</b></span>
            <span>样本 <b>{rtt.samples}</b></span>
            <span title="frame.cap_len < frame.len 的帧:抓包工具没抓全(采集侧信号),不是网络丢包证据">
              截断帧 <b>{cq.available ? cq.truncatedCount : '—'}</b>
            </span>
            <span title="frame.cap_len < frame.len 的帧:抓包工具没抓全(采集侧信号),不是网络丢包证据">
              截断帧 <b>{cq.available ? cq.truncatedCount : '—'}</b>
            </span>
            <span>
              截断占比 <b>{cq.available ? `${(cq.truncatedRatio! * 100).toFixed(1)}%` : 'unavailable'}</b>
            </span>
            <span title="对端通告的接收窗口:最小值贴近 0 说明对端缓冲吃紧。窗口字节数是通告值,单观察点不见实际缓冲区">
              窗口 min <b>{ws?.available ? `${(ws.minBytes! / 1024).toFixed(1)}KB` : '—'}</b>
            </span>
            <span>窗口 max <b>{ws?.available ? `${(ws.maxBytes! / 1024).toFixed(1)}KB` : '—'}</b></span>
            <span>窗口变化 <b>{ws?.available ? ws.changes : '—'}</b></span>
            {ws && ws.zeroCount > 0 && (
              <span title="通告值连续为 0 的期数(合并计);零窗口本身是流量控制,长期未重开才值得关注">
                零窗口期 <b>{ws.zeroCount}</b>
              </span>
            )}
          </div>
          {cq.available && cq.truncatedCount > 0 && (
            <div className="issue-line" title={`截断帧:#${cq.truncatedPackets.join(', #')}`}>
              ⚠ 存在截断帧(snaplen/采集口限制):这些报文的载荷分析受限;截断是采集侧信号,不指示网络丢包
            </div>
          )}
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
