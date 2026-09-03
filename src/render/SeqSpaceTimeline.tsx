import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { computeSeqSpaceLayout, type SeqSpaceLane } from './seqSpace.ts'
import { wheelZoom } from '../m4/viewModel'
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
 * 交互(2026-09-02 用户要求:大会话太紧凑,与故障分析同款缩放):
 * 滚轮以指针位置为锚缩放、按住拖拽平移、双击复位 —— 与 SeqSpaceGraphic
 * 的 zoomRange/onZoomRange 同一套语义;窗口状态归组件(每方向带独立)。
 *
 * 布局逻辑在 seqSpace.ts 纯函数中,本组件只做 SVG 映射;报文标记可点击
 * (onSelect 帧号),与其它形态的点击详情联动一致。
 */

/** 字节轴缩放窗口(null = 全轴;与 FaultCompare.ZoomRange 同构) */
interface AxisWindow {
  start: number
  end: number
}

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
  // 每方向带的缩放窗口(切会话整体复位)
  const [windows, setWindows] = useState<Record<string, AxisWindow | null>>({})
  useEffect(() => {
    setWindows({})
  }, [conv])
  const svgElRef = useRef<SVGSVGElement | null>(null)
  const dragRef = useRef<{ pointerId: number; x: number; laneKey: string; win: AxisWindow; width: number; moved: boolean } | null>(null)

  // 占满容器(用户要求 2026-09-02:整页板块右侧留白太怪):viewBox 宽跟随
  // 容器实际宽度(布局 720 只是下限),ResizeObserver 监听;jsdom 无布局,
  // window resize 兜底。SVG 按 viewBox 拉伸后字体/图元等比放大,清晰不挤。
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const [wrapWidth, setWrapWidth] = useState(0)
  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const measure = (): void => {
      const w = el.getBoundingClientRect().width
      if (w > 0) setWrapWidth(Math.floor(w))
    }
    measure()
    if (typeof ResizeObserver !== 'undefined') {
      const ro = new ResizeObserver(measure)
      ro.observe(el)
      return () => ro.disconnect()
    }
    // jsdom 兜底:window resize + 测试钩子
    window.addEventListener('resize', measure)
    ;(window as unknown as { __seqspResize?: () => void }).__seqspResize = measure
    return () => {
      window.removeEventListener('resize', measure)
      delete (window as unknown as { __seqspResize?: () => void }).__seqspResize
    }
  }, [])

  // 双击复位所有带窗口(简明交互:全图回到全轴)
  const resetWindows = useCallback(() => setWindows({}), [])

  // 滚轮缩放:以指针在带内的横向位置为锚;根据 y 找到所在带(独立窗口)。
  // 仅当已有带缩放(非全轴)时 preventDefault 拦截容器滚动 —— 全轴状态滚轮
  // 交还容器(多带会话图高超过滚动容器时,指针在 svg 上滚轮必须还能上下滚动),
  // 缩放依然执行:浏览器原生滚轮在「未被 preventDefault」时按轴距滚动容器,
  // 但 deltaY 缩放本就要跟随指针位置,容器微滚不影响当前带,故不冲突。
  const onWheelNative = useCallback(
    (ev: WheelEvent) => {
      const zoomed = zoomedRef.current
      if (zoomed) ev.preventDefault()
      const svg = svgElRef.current
      if (!svg || layout.lanes.length === 0) return
      const rect = svg.getBoundingClientRect()
      // 布局宽与显示宽的换算(viewBox 720 vs 实际 rect.width)
      const frac = rect.width > 0 ? (ev.clientX - rect.left) / rect.width : 0.5
      // y → 带下标
      const vbH = Math.max(layout.lanes.length * (LANE_H + LANE_GAP), LANE_H)
      const fracY = rect.height > 0 ? (ev.clientY - rect.top) / rect.height : 0
      const li = Math.min(layout.lanes.length - 1, Math.max(0, Math.floor(fracY * vbH / (LANE_H + LANE_GAP))))
      const lane = layout.lanes[li]
      if (!lane) return
      const key = `${lane.kind}-${lane.direction}-${li}`
      setWindows((prev) => {
        const cur = prev[key] ?? null
        const next = wheelZoom(lane.axisMin, lane.axisMax, cur, frac, ev.deltaY)
        return { ...prev, [key]: next.end - next.start >= lane.axisMax - lane.axisMin - 1e-9 ? null : next }
      })
    },
    [layout.lanes],
  )
  useEffect(() => {
    const svg = svgElRef.current
    if (!svg) return
    svg.addEventListener('wheel', onWheelNative, { passive: false })
    return () => svg.removeEventListener('wheel', onWheelNative)
  }, [onWheelNative])

  // 拖拽平移:横向像素位移换算字节位移,窗口钳制在轴内。
  // 滚轮状态:仅当有带已缩放(窗口非全轴)时拦截 preventDefault,
  // 全轴状态交还容器默认滚动(多带会话图高超过容器时,指针在 svg 上滚轮仍可上下滚动)
  const zoomedRef = useRef(false)
  zoomedRef.current = Object.values(windows).some((w) => w != null)
  // 点击护栏(用户实测:点报文无详情):pointerdown 只记录起点、**不捕获指针** ——
  // setPointerCapture 会把后续 click 的 target 重定向到捕获元素(svg 根),
  // 图元的 onClick 永远收不到(真实浏览器行为,jsdom 模拟不出)。改为移动超过
  // 4px 才算拖拽(阈值内视为点击,浏览器原生 click 正常派发到图元)。
  const DRAG_THRESHOLD_PX = 4
  const onPointerDown = useCallback(
    (e: React.PointerEvent<SVGSVGElement>) => {
      const svg = svgElRef.current
      if (!svg || layout.lanes.length === 0) return
      const rect = svg.getBoundingClientRect()
      const vbH = Math.max(layout.lanes.length * (LANE_H + LANE_GAP), LANE_H)
      const fracY = rect.height > 0 ? (e.clientY - rect.top) / rect.height : 0
      const li = Math.min(layout.lanes.length - 1, Math.max(0, Math.floor(fracY * vbH / (LANE_H + LANE_GAP))))
      const lane = layout.lanes[li]
      if (!lane) return
      const key = `${lane.kind}-${lane.direction}-${li}`
      const win = windows[key] ?? { start: lane.axisMin, end: lane.axisMax }
      // moved=false:尚未超过阈值,是"潜在点击";拖动才置 true(此时才开始平移)
      dragRef.current = { pointerId: e.pointerId, x: e.clientX, laneKey: key, win, width: rect.width, moved: false }
    },
    [layout.lanes, windows],
  )
  const onPointerMove = useCallback(
    (e: React.PointerEvent<SVGSVGElement>) => {
      const d = dragRef.current
      if (!d || d.pointerId !== e.pointerId) return
      const dx = e.clientX - d.x
      if (!d.moved && Math.abs(dx) < DRAG_THRESHOLD_PX) return // 未达阈值:不动作,留给 click
      const lane = layout.lanes.find((_, i) => `${layout.lanes[i].kind}-${layout.lanes[i].direction}-${i}` === d.laneKey)
      if (!lane) return
      const span = d.win.end - d.win.start
      const full = lane.axisMax - lane.axisMin
      if (span >= full) return // 未缩放时无可平移范围
      d.moved = true
      const dBytes = -(dx / Math.max(d.width, 1)) * span
      let s0 = d.win.start + dBytes
      s0 = Math.min(Math.max(s0, lane.axisMin), lane.axisMax - span)
      setWindows((prev) => ({ ...prev, [d.laneKey]: { start: s0, end: s0 + span } }))
    },
    [layout.lanes],
  )
  const onPointerUp = useCallback((e: React.PointerEvent<SVGSVGElement>) => {
    if (dragRef.current?.pointerId === e.pointerId) dragRef.current = null
  }, [])

  if (!conv) {
    return <div className="empty">从左侧选择一个会话查看时序图</div>
  }

  // 画布宽:容器实际宽优先(占满面板,整页板块不再右侧留白),布局 720 为下限
  const width = Math.max(wrapWidth, layout.width)
  const height = Math.max(layout.lanes.length * (LANE_H + LANE_GAP), LANE_H)
  const zoomedAny = Object.values(windows).some((w) => w != null)

  return (
    <div
      ref={wrapRef}
      className="seq-wrap"
      style={{ flex: 1, overflow: 'auto', position: 'relative', background: '#f8fafc', border: '1px solid #eef2f7', borderRadius: 8, padding: 8 }}
    >
      {conv.issues.length > 0 && (
        <div className="issue-banner">⚠ {conv.issues.map((i) => i.message).join('；')}</div>
      )}
      {layout.lanes.length === 0 && (
        <div className="many-warn" style={{ margin: '2px 0 4px' }}>
          该会话没有可还原序列空间的 TCP 数据段(非 TCP 或缺少 seq/len 字段)
        </div>
      )}
      {zoomedAny && (
        <div className="many-warn" style={{ margin: '2px 0 4px' }}>
          已放大局部视图:滚轮缩放 · 拖拽平移 · 双击复位
        </div>
      )}
      <svg
        ref={(el) => {
          svgElRef.current = el
          // 外部 svgRef(导出 PNG 用)也要接到同一元素
          if (typeof svgRef === 'object' && svgRef !== null) (svgRef as { current: SVGSVGElement | null }).current = el
        }}
        data-testid="seq-space-timeline"
        width={width * zoom}
        height={height * zoom}
        viewBox={`0 0 ${width} ${height}`}
        style={{ display: 'block', font: '11px system-ui, sans-serif', maxWidth: '100%', cursor: zoomedAny ? 'grab' : undefined }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onDoubleClick={resetWindows}
      >
        <defs>
          <pattern id="seqsp-hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
            <rect width="6" height="6" fill="#fee2e2" />
            <line x1="0" y1="0" x2="0" y2="6" stroke="#ef4444" strokeWidth="2" />
          </pattern>
          <marker id="seqsp-arr" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
            <path d="M0,0 L7,3 L0,6 z" fill="#94a3b8" />
          </marker>
        </defs>
        {layout.lanes.map((lane, li) => {
          const top = li * (LANE_H + LANE_GAP)
          const key = `${lane.kind}-${lane.direction}-${li}`
          const win = windows[key] ?? null
          // x 映射按当前窗口(未缩放时即全轴);跨窗口的图元做像素级裁剪交由
          // SVG overflow 即可,窗口由 wheelZoom/拖拽钳制在轴内
          const viewMin = win ? win.start : lane.axisMin
          const viewMax = win ? win.end : lane.axisMax
          const span = viewMax - viewMin || 1
          // TCP 带预留左侧方向列(标注客户端/服务端→),回退带用窄边距
          const plotLeft = lane.kind === 'tcp' ? DIR_LABEL_COL : W_PAD
          const x = (v: number): number => ((v - viewMin) / span) * (width - W_PAD * 2 - DIR_LABEL_COL) + plotLeft
          return (
            <g key={key} transform={`translate(0 ${top})`}>
              <LaneGraphic
                lane={lane}
                x={x}
                width={width}
                onSelect={onSelect}
                hlSet={hlSet}
                laneIndex={li}
                plotLeft={plotLeft}
                viewMin={viewMin}
                viewMax={viewMax}
                zoomed={win != null}
              />
            </g>
          )
        })}
      </svg>
    </div>
  )
}

/** TCP 带左侧方向标注列宽(客户端→ / 服务端→);字节条从其后起算 */
const DIR_LABEL_COL = 62

function LaneGraphic({
  lane,
  x,
  width,
  onSelect,
  hlSet,
  laneIndex,
  plotLeft,
  viewMin,
  viewMax,
  zoomed,
}: {
  lane: SeqSpaceLane
  x: (v: number) => number
  width: number
  onSelect: (n: number) => void
  hlSet: Set<number> | null
  laneIndex: number
  /** 绘图区左边界(TCP 带=方向列后;回退带=窄边距) */
  plotLeft: number
  /** 当前可见轴窗口(滚轮缩放/拖拽后变化;默认全轴) */
  viewMin: number
  viewMax: number
  zoomed: boolean
}) {
  // 窗口外图元直接不渲染(缩放后清晰度交给矢量映射,数量也随窗口收窄)。
  // 点图元(s==e,如回退带报文点)用闭区间判定:正好落在窗口边界仍可见
  const inView = (s: number, e: number): boolean => (s === e ? s >= viewMin && s <= viewMax : e > viewMin && s < viewMax)
  // 窗口内刻度:1/2/5 步长(与全轴同规则,基于可见窗口)
  const ticks = zoomed ? laneTicks(viewMin, viewMax) : lane.ticks
  return (
    <g data-testid={`seqsp-lane-${laneIndex}`}>
      {/* 带标题:方向端点对(回退带含协议名) */}
      <text x={plotLeft} y={12} fontSize={10} fill="#94a3b8">
        {lane.label}
        {zoomed ? ` · 放大 ${Math.round(viewMin)}–${Math.round(viewMax)}` : ''}
      </text>
      {/* 轴说明(只画在第一条带):TCP 带=字节序列空间;回退带=时间轴(相对秒) */}
      {laneIndex === 0 && (
        <text x={width - W_PAD} y={12} textAnchor="end" fontSize={10} fill="#94a3b8">
          {layoutCaption(lane.kind)}
        </text>
      )}

      {/* 方向标注(TCP 带左列:上下两行分别是「客户端→服务端」/「服务端→客户端」,
          数据流方向一眼可辨;用户要求 2026-09-02) */}
      {lane.kind === 'tcp' && (
        <text x={W_PAD + 4} y={BAR_Y + BAR_H / 2 + 3} fontSize={10} fontWeight="bold" fill={lane.direction === 'c2s' ? '#1d4ed8' : '#c2410c'}>
          {lane.direction === 'c2s' ? '客户端 →' : '服务端 →'}
        </text>
      )}
      {/* 已见字节条(事实层:抓包看见过的字节;窗口外不渲染) */}
      {lane.seenRuns.filter(([s, e]) => inView(s, e)).map(([s, e], i) => (
        <rect key={`seen${i}`} x={x(s)} y={BAR_Y} width={Math.max(x(e) - x(s), 1)} height={BAR_H} fill={SEEN} rx={2}>
          <title>{`已见字节 ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* 缺口:红斜纹 */}
      {lane.gaps.filter(([s, e]) => inView(s, e)).map(([s, e], i) => (
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
      {lane.sackBlocks.filter(([s, e]) => inView(s, e)).map(([s, e], i) => (
        <rect key={`sack${i}`} x={x(s)} y={SACK_Y} width={Math.max(x(e) - x(s), 2)} height={SACK_H} fill={SACK} rx={2}>
          <title>{`SACK(对端已收) ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* SACK 行内说明:与最后一个 SACK 块左对齐(不再固定贴右边与块重叠) */}
      {lane.sackBlocks.length > 0 && (
        <text
          x={Math.min(x(lane.sackBlocks[lane.sackBlocks.length - 1][0]), width - W_PAD - 90)}
          y={SACK_Y + 8}
          textAnchor="start"
          fontSize={9}
          fill="#7c3aed"
        >
          对端已收(SACK)
        </text>
      )}
      {/* 重传标记(红条,叠在 SACK 行;title 即说明,不再另画文字) */}
      {lane.retxMarks.filter((m) => inView(m.seq, m.seq + Math.max(m.len, 1))).map((m, i) => {
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
      {/* 证据链关键报文标注:暴露缺口/补缺口/恢复 ACK(三角;点击跳详情)。
          帧号文字按像素防叠:与前一个标注距离 < 26px 的只画三角不画字。
          缩放后窗口收窄,可见标注变少 → 防叠间距阈值也随之放宽(窗口内 26px 恒定) */}
      {(() => {
        const shown: React.ReactNode[] = []
        let lastTextX = -Infinity
        lane.marks
          .filter((m) => m.kind !== 'retx' && m.seq >= viewMin - 1e9 && m.seq <= viewMax + 1e9)
          .forEach((m, i) => {
            const px = x(m.seq)
            const isHl = hlSet?.has(m.packetNumber) ?? false
            const color = m.kind === 'ack' ? ACK : m.kind === 'fill' ? SEEN : RETX
            const showText = px - lastTextX >= 26
            if (showText) lastTextX = px
            shown.push(
              <g key={`mk${i}`} data-pkt={m.packetNumber} style={{ cursor: 'pointer' }} onClick={() => onSelect(m.packetNumber)}>
                <title>{`#${m.packetNumber} ${m.kind === 'ack' ? '恢复确认' : m.kind === 'fill' ? '补缺口' : '暴露缺口'}(点击查看报文)`}</title>
                <path d={`M${px - 4},${LABEL_Y + 6} L${px + 4},${LABEL_Y + 6} L${px},${LABEL_Y - 1} z`} fill={isHl ? ACK : color} />
                {showText && (
                  <text x={px} y={LABEL_Y + 16} textAnchor="middle" fontSize={8.5} fill={isHl ? ACK : color}>
                    {`#${m.packetNumber}`}
                  </text>
                )}
                <rect x={px - 8} y={LABEL_Y - 4} width={16} height={24} fill="transparent" />
              </g>,
            )
          })
        return shown
      })()}
      {/* 非 TCP 回退时间轴带:线条交互图(用户要求 2026-09-02:ICMP 等也要
          线条形式,不是点点点)。上下两条端点行,每报文一条水平线段:
          a2b 左→右(蓝),b2a 右→左(橙,与 A/B 形态方向色一致),中性虚线;
          t 时刻落位,帧号标注在线上方,点击跳详情 */}
      {(() => {
        if (lane.messages.length === 0) return null
        const TOP_Y = BAR_Y // 上行端点(a2b 出发侧)
        const BOT_Y = BAR_Y + BAR_H + 16 // 下行端点(b2a 出发侧)
        const lineColor = (d: string): string => (d === 'a2b' ? '#3b82f6' : d === 'b2a' ? '#f97316' : '#94a3b8')
        return (
          <>
            {/* 两端点行基线 */}
            <line x1={W_PAD} y1={TOP_Y} x2={width - W_PAD} y2={TOP_Y} stroke="#cbd5e1" strokeDasharray="4 4" />
            <line x1={W_PAD} y1={BOT_Y} x2={width - W_PAD} y2={BOT_Y} stroke="#cbd5e1" strokeDasharray="4 4" />
            {lane.messages.filter((m) => inView(m.t, m.t)).map((m, i) => {
              const px = x(m.t)
              const isHl = hlSet?.has(m.packetNumber) ?? false
              const color = m.anomaly ? '#ea580c' : lineColor(m.dir)
              // 线段:从出发端点行横跨到对侧(a2b 上→下、b2a 下→上);终点箭头
              const fromY = m.dir === 'b2a' ? BOT_Y : TOP_Y
              const toY = m.dir === 'b2a' ? TOP_Y : BOT_Y
              const arrowX = m.dir === 'b2a' ? Math.max(px - 7, W_PAD) : Math.min(px + 7, width - W_PAD)
              const labelY = m.dir === 'b2a' ? BOT_Y + 14 : TOP_Y - 6
              return (
                <g key={`msg${i}`} data-testid="seqsp-msg" data-pkt={m.packetNumber} style={{ cursor: 'pointer' }} onClick={() => onSelect(m.packetNumber)}>
                  <title>{`${m.label}(点击查看报文)`}</title>
                  <circle cx={px} cy={fromY} r={3.5} fill={color} stroke="#fff" strokeWidth={1} />
                  {m.dir === 'neutral' ? (
                    <line x1={px} y1={fromY} x2={px} y2={toY} stroke={color} strokeWidth={1.6} strokeDasharray="2 3" />
                  ) : (
                    <line x1={px} y1={fromY} x2={arrowX} y2={toY} stroke={color} strokeWidth={1.6} markerEnd="url(#seqsp-arr)" />
                  )}
                  <text x={px} y={labelY} textAnchor="middle" fontSize={8.5} fill={isHl ? ACK : color}>
                    {`#${m.packetNumber}`}
                  </text>
                  <rect x={px - 8} y={Math.min(fromY, toY) - 4} width={16} height={Math.abs(toY - fromY) + 8} fill="transparent" />
                </g>
              )
            })}
          </>
        )
      })()}
      {/* ACK 游标:累计确认位置(游标卡在缺口前 = 对端没收到缺口数据);
          标签贴画布边缘时锚点内移,避免文字被裁掉一半 */}
      {lane.finalAck != null && lane.finalAck >= viewMin && lane.finalAck <= viewMax && (
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
      {/* 字节刻度轴;两端刻度文字锚点内移,避免数字被画布边缘裁掉;
          缩放时刻度按可见窗口 1/2/5 重算(密度恒定) */}
      <g data-testid="seqsp-ticks">
        <line x1={W_PAD} y1={TICK_LINE_Y} x2={width - W_PAD} y2={TICK_LINE_Y} stroke={AXIS} />
        {ticks.map((t, ti) => {
          const tx = x(t)
          const anchor = tx < W_PAD + 20 ? 'start' : tx > width - W_PAD - 20 ? 'end' : 'middle'
          const ax = anchor === 'start' ? W_PAD : anchor === 'end' ? width - W_PAD : tx
          // 时间轴的小数刻度四舍五入后可能撞值(0.2 与 0.25 → 同 0.2):key 带下标防撞
          const tickLabel = lane.kind === 'fallback' ? (t < 1 ? t.toFixed(2) : String(t)) : String(t)
          return (
            <g key={`${t}-${ti}`}>
              <line x1={tx} y1={TICK_LINE_Y} x2={tx} y2={TICK_LINE_Y + 4} stroke={AXIS} />
              <text x={ax} y={TICK_LINE_Y + 16} textAnchor={anchor} fontSize={10} fill={TICK_TEXT}>
                {tickLabel}
              </text>
            </g>
          )
        })}
      </g>
    </g>
  )
}

/** 窗口内 1/2/5 整步长刻度(与 seqSpace.ticksFor 同规则;组件内独立实现避免反向依赖) */
function laneTicks(viewMin: number, viewMax: number): number[] {
  if (viewMax <= viewMin) return []
  const rawStep = (viewMax - viewMin) / 5
  const mag = Math.pow(10, Math.floor(Math.log10(rawStep)))
  const norm = rawStep / mag
  const step = (norm >= 5 ? 5 : norm >= 2 ? 2 : 1) * mag
  const out: number[] = []
  for (let t = Math.ceil(viewMin / step) * step; t <= viewMax; t += step) {
    out.push(Math.round(t * 10) / 10)
  }
  return out
}

/** 轴说明文案:TCP=字节序列空间读法;回退=时间轴线条读法 */
function layoutCaption(kind: 'tcp' | 'fallback'): string {
  return kind === 'tcp'
    ? '序列号空间(字节) · 绿=已收 红纹=未收到 紫=SACK(对端已收) 蓝=累计确认 红=重传'
    : '时间轴(相对秒) · 线=报文(点击看详情) 蓝=发出 橙=返回 橙线=带分析标记'
}
