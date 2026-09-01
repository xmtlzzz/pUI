import { useMemo, type RefObject } from 'react'
import { computeSeqSpaceLayout, type SeqSpaceLane } from './seqSpace.ts'
import type { Conversation } from '../model/types'

/**
 * 序列号空间形态时序图(用户要求 2026-09-01:要第二张图 —— FaultCompare
 * 序列空间条带图的那种读法,而不是横过来的报文交互箭头)。
 *
 * 每方向一条带(c2s 在上 / s2c 在下,两个 ISN 空间不混轴),每条带复刻
 * 同一视觉语言:绿=已收数据条,红斜纹=未收到缺口,紫=对端已收(SACK),
 * 蓝游标=累计确认 ACK,红条=重传;底部字节刻度。配色与 FaultCompare
 * 的 SeqSpaceGraphic 完全一致(全局一套序列空间语义色,不另起炉灶)。
 *
 * 布局逻辑在 seqSpace.ts 纯函数中,本组件只做 SVG 映射;报文标记可点击
 * (onSelect 帧号),与其它形态的点击详情联动一致。
 */

export interface SeqSpaceTimelineProps {
  conv: Conversation | null
  highlight?: readonly number[]
  onSelect: (n: number) => void
  svgRef: RefObject<SVGSVGElement | null>
  /** 盒尺寸缩放:乘 width/height(盒尺寸模式与其它形态一致) */
  zoom: number
}

// —— 与 FaultCompare.SeqSpaceGraphic 同一套语义色 ——
const SEEN = '#10b981'
const SACK = '#8b5cf6'
const ACK = '#1d4ed8'
const RETX = '#ef4444'
const GAP_FILL = 'url(#seqsp-hatch)'
const AXIS = '#cbd5e1'
const TICK_TEXT = '#64748b'

/** viewBox 几何:左右边距 8;每带高度与带间距 */
const W_PAD = 8
const BAR_Y = 30 // 带内主条 y(相对带顶;与 FaultCompare 的 30 一致)
const BAR_H = 14
const SACK_Y = 48
const SACK_H = 10
const LABEL_Y = 72
const ACK_Y = 92
const TICK_LINE_Y = 128
const LANE_H = 150 // 与 FaultCompare H=150 同档
const LANE_GAP = 10

export function SeqSpaceTimeline({ conv, highlight, onSelect, svgRef, zoom }: SeqSpaceTimelineProps) {
  const layout = useMemo(() => computeSeqSpaceLayout(conv ? conv.packets : [], { client: conv?.client ?? '' }), [conv])
  const hlSet = useMemo(() => (highlight ? new Set(highlight) : null), [highlight])

  if (!conv) {
    return <div className="empty">从左侧选择一个会话查看时序图</div>
  }

  const width = layout.width
  const height = Math.max(layout.lanes.length * (LANE_H + LANE_GAP), LANE_H)

  return (
    <div className="seq-wrap" style={{ flex: 1, overflow: 'auto', position: 'relative', background: '#f8fafc', border: '1px solid #eef2f7', borderRadius: 8, padding: 8 }}>
      {conv.issues.length > 0 && (
        <div className="issue-banner">⚠ {conv.issues.map((i) => i.message).join('；')}</div>
      )}
      {layout.lanes.length === 0 && (
        <div className="many-warn" style={{ margin: '2px 0 4px' }}>
          该会话没有可还原序列空间的 TCP 数据段(非 TCP 或缺少 seq/len 字段)
        </div>
      )}
      <svg
        ref={svgRef}
        data-testid="seq-space-timeline"
        width={width * zoom}
        height={height * zoom}
        viewBox={`0 0 ${width} ${height}`}
        style={{ display: 'block', font: '11px system-ui, sans-serif', maxWidth: '100%' }}
      >
        <defs>
          <pattern id="seqsp-hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
            <rect width="6" height="6" fill="#fee2e2" />
            <line x1="0" y1="0" x2="0" y2="6" stroke="#ef4444" strokeWidth="2" />
          </pattern>
        </defs>
        {layout.lanes.map((lane, li) => {
          const top = li * (LANE_H + LANE_GAP)
          const span = lane.axisMax - lane.axisMin || 1
          const x = (v: number): number => ((v - lane.axisMin) / span) * (width - W_PAD * 2) + W_PAD
          return (
            <g key={lane.direction} transform={`translate(0 ${top})`}>
              <LaneGraphic lane={lane} x={x} width={width} onSelect={onSelect} hlSet={hlSet} laneIndex={li} />
            </g>
          )
        })}
      </svg>
    </div>
  )
}

function LaneGraphic({
  lane,
  x,
  width,
  onSelect,
  hlSet,
  laneIndex,
}: {
  lane: SeqSpaceLane
  x: (v: number) => number
  width: number
  onSelect: (n: number) => void
  hlSet: Set<number> | null
  laneIndex: number
}) {
  return (
    <g data-testid={`seqsp-lane-${laneIndex}`}>
      {/* 带标题:方向端点对 */}
      <text x={W_PAD} y={12} fontSize={10} fill="#94a3b8">
        {lane.label}
      </text>
      {/* 轴说明(只画在第一条带) */}
      {laneIndex === 0 && (
        <text x={width - W_PAD} y={12} textAnchor="end" fontSize={10} fill="#94a3b8">
          序列号空间(字节) · 绿=已收 红纹=未收到 紫=SACK(对端已收) 蓝=累计确认 红=重传
        </text>
      )}

      {/* 已见字节条(事实层:抓包看见过的字节) */}
      {lane.seenRuns.map(([s, e], i) => (
        <rect key={`seen${i}`} x={x(s)} y={BAR_Y} width={Math.max(x(e) - x(s), 1)} height={BAR_H} fill={SEEN} rx={2}>
          <title>{`已见字节 ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* 缺口:红斜纹 */}
      {lane.gaps.map(([s, e], i) => (
        <rect
          key={`gap${i}`}
          data-testid={`seqsp-gap-${laneIndex}-${i}`}
          x={x(s)}
          y={BAR_Y}
          width={Math.max(x(e) - x(s), 2)}
          height={BAR_H}
          fill={GAP_FILL}
          stroke="#ef4444"
          strokeDasharray="3 2"
        >
          <title>{`未收到 ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* SACK 块(紫):对端报告已收、本抓包点未必见过的字节 */}
      {lane.sackBlocks.map(([s, e], i) => (
        <rect key={`sack${i}`} x={x(s)} y={SACK_Y} width={Math.max(x(e) - x(s), 2)} height={SACK_H} fill={SACK} rx={2}>
          <title>{`SACK(对端已收) ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {lane.sackBlocks.length > 0 && (
        <text x={width - W_PAD} y={SACK_Y + 8} textAnchor="end" fontSize={9} fill="#7c3aed">
          对端已收(SACK)
        </text>
      )}
      {/* 重传标记(红条,叠在主条下沿) */}
      {lane.retxMarks.map((m, i) => {
        const x0 = x(m.seq)
        const x1 = x(m.seq + Math.max(m.len, 1))
        const key = `retx-${m.packetNumber}-${i}`
        return (
          <g key={key} data-testid="seqsp-retx" data-pkt={m.packetNumber} style={{ cursor: 'pointer' }} onClick={() => onSelect(m.packetNumber)}>
            <title>{`#${m.packetNumber} 重传 seq=${m.seq} len=${m.len}(点击查看报文)`}</title>
            <rect x={x0} y={SACK_Y} width={Math.max(x1 - x0, 3)} height={7} fill={RETX} rx={1.5} />
            <rect x={x0 - 4} y={SACK_Y - 4} width={Math.max(x1 - x0, 3) + 8} height={15} fill="transparent" />
          </g>
        )
      })}
      {/* 证据链关键报文标注:暴露缺口/补缺口/恢复 ACK(三角 + #帧号;点击跳详情) */}
      {lane.marks
        .filter((m) => m.kind !== 'retx')
        .map((m, i) => {
          const px = x(m.seq)
          const isHl = hlSet?.has(m.packetNumber) ?? false
          const color = m.kind === 'ack' ? ACK : m.kind === 'fill' ? SEEN : RETX
          return (
            <g key={`mk${i}`} data-pkt={m.packetNumber} style={{ cursor: 'pointer' }} onClick={() => onSelect(m.packetNumber)}>
              <title>{`#${m.packetNumber} ${m.kind === 'ack' ? '恢复确认' : m.kind === 'fill' ? '补缺口' : '暴露缺口'}(点击查看报文)`}</title>
              <path d={`M${px - 4},${LABEL_Y + 6} L${px + 4},${LABEL_Y + 6} L${px},${LABEL_Y - 1} z`} fill={isHl ? ACK : color} />
              <text x={px} y={LABEL_Y + 16} textAnchor="middle" fontSize={8.5} fill={isHl ? ACK : color}>
                {`#${m.packetNumber}`}
              </text>
              <rect x={px - 8} y={LABEL_Y - 4} width={16} height={24} fill="transparent" />
            </g>
          )
        })}
      {/* ACK 游标:累计确认位置(游标卡在缺口前 = 对端没收到缺口数据);
          标签贴画布边缘时锚点内移,避免文字被裁掉一半 */}
      {lane.finalAck != null && (
        <g data-testid={`seqsp-ack-${laneIndex}`}>
          {(() => {
            const cx = x(lane.finalAck)
            const label = `累计确认 ACK ${lane.finalAck}`
            const halfW = label.length * 5.5
            const anchor = cx - halfW < W_PAD ? 'start' : cx + halfW > width - W_PAD ? 'end' : 'middle'
            const tx = anchor === 'start' ? W_PAD : anchor === 'end' ? width - W_PAD : cx
            return (
              <>
                <line x1={cx} y1={ACK_Y} x2={cx} y2={TICK_LINE_Y} stroke={ACK} strokeWidth={1.5} strokeDasharray="4 3" />
                <circle cx={cx} cy={ACK_Y} r={5} fill={ACK} />
                <text x={tx} y={ACK_Y - 8} textAnchor={anchor} fontSize={10} fill={ACK}>
                  {label}
                </text>
              </>
            )
          })()}
        </g>
      )}
      {/* 字节刻度轴;两端刻度文字锚点内移,避免数字被画布边缘裁掉 */}
      <g data-testid="seqsp-ticks">
        <line x1={W_PAD} y1={TICK_LINE_Y} x2={width - W_PAD} y2={TICK_LINE_Y} stroke={AXIS} />
        {lane.ticks.map((t) => {
          const tx = x(t)
          const anchor = tx < W_PAD + 20 ? 'start' : tx > width - W_PAD - 20 ? 'end' : 'middle'
          const ax = anchor === 'start' ? W_PAD : anchor === 'end' ? width - W_PAD : tx
          return (
            <g key={t}>
              <line x1={tx} y1={TICK_LINE_Y} x2={tx} y2={TICK_LINE_Y + 4} stroke={AXIS} />
              <text x={ax} y={TICK_LINE_Y + 16} textAnchor={anchor} fontSize={10} fill={TICK_TEXT}>
                {t}
              </text>
            </g>
          )
        })}
      </g>
    </g>
  )
}
