import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { clipSeqSpaceView, popIn, SEQ_STAGE_COLORS, wheelZoom, windowProgress, zoomStep } from '../m4/viewModel'
import type { AppImpact } from '../analysis/app/impact'
import type { CompareEventSummary, CompareViewModel, SeqSpaceView } from '../m4/viewModel'
import { usePlayback, type PlaybackPhase } from '../m4/usePlayback'
import './faultCompare.css'

/**
 * M4 故障/正常对照页(整页板块)。
 *
 * 布局(用户审批反馈 2026-08-26 第二轮):
 * - 整页切换:进入故障分析时工具的整个工作区切换到本板块,可返回;
 * - 左栏核心是**序列空间图形化**(已见字节条 + Gap hatch + SACK 绿块 + 重传回补箭头 +
 *   ACK 游标),不是逐报文列表 —— VDI 抓包数千报文的列表不可用;
 * - 左栏顶部为**事件切换器**:VDI 实测一个会话常有大量缺口事件,只看 events[0] 不可用;
 *   切换事件由父层重算视图模型,本组件以 eventKey 重挂载来复位播放状态;
 * - 阶段带为时间进度条形态(DSH duration 式):彩色阶段段 + 当前位置游标 + 刻度,
 *   当前阶段信息面板固定展示;
 * - 关键报文链只含证据链报文(点击跳回原报文)。
 */

/** 跳回原报文时随行的对照页位置(事件下标+活动阶段下标),父层据此支持返回恢复 */
export interface JumpContext {
  eventIndex: number
  stageIndex: number
}

interface FaultCompareProps {
  vm: CompareViewModel | null
  onSelectPacket: (n: number, ctx?: JumpContext) => void
  onBack: () => void
  /** 事件切换器数据(可选;不传或为空时不渲染切换器) */
  events?: CompareEventSummary[]
  /** 当前选中事件下标 */
  eventIndex?: number
  /** 切换事件回调;eventKey 变化时内容区整体重挂载(播放复位) */
  onSelectEvent?: (i: number) => void
  /** 当前事件的稳定 id,作为内容区 remount key */
  eventKey?: string
  /** 从报文详情返回时的初始阶段下标(挂载时转成阶段起点时刻,仅初始化生效) */
  initialStageIndex?: number
  /** 导出当前事件为 Markdown 证据报告(实际故障侧;正常参考不导出) */
  onExport?: () => void
  /** 导出当前事件为版本化 JSON 证据(schema pui-evidence,与 Markdown 报告同口径) */
  onExportEvidence?: () => void
  /**
   * 同期应用层关联(M6):当前 TCP 事件与 HTTP/DNS/TLS 事件的时间窗重叠,
   * 措辞已在 correlateImpacts 限定("同期现象,可能相关,不构成因果");
   * 点击条目跳到对应应用层报文。空/缺省不渲染该区。
   */
  appImpacts?: AppImpact[]
  /**
   * 会话两端身份(可选,「客户端 → 服务端」展示):传入后方向切换器用端点身份
   * + 箭头标注数据方向,替代 c2s/s2c 黑话;不传时退化为事件方向/对向
   */
  endpoints?: { client: string; server: string }
}

function phaseLabel(p: PlaybackPhase): string {
  switch (p) {
    case 'playing':
      return '播放中'
    case 'paused':
      return '已暂停'
    case 'done':
      return '终态'
    case 'static':
      return '静态模式'
    default:
      return '待播放'
  }
}

/** 事件切换器虚拟化阈值:低于此值直接全渲染(常规会话 <100 事件,虚拟化反增复杂度) */
export const EV_VIRTUAL_THRESHOLD = 60
/** 虚拟化模式下单事件按钮的固定高度(px,与 .fc-evbtn 实测渲染高度一致,上下含 gap 6px) */
const EV_ITEM_H = 52
const EV_GAP = 6
/** 可视区上下各多渲染的行数(滚动缓冲,防白边) */
const EV_OVERSCAN = 4

/**
 * 事件切换器(检出的事件列表)。事件少时全渲染;
 * 多时窗口虚拟化:容器固定高滚动,只挂载可视区按钮(上下留 overscan),
 * 占位高度用总高撑起滚动条。选中项变化时自动滚动到可视区。
 */
export function EventSwitcher({
  events,
  eventIndex,
  onSelectEvent,
}: {
  events: CompareEventSummary[]
  eventIndex: number
  onSelectEvent: (i: number) => void
}) {
  const virtual = events.length > EV_VIRTUAL_THRESHOLD
  const [scrollTop, setScrollTop] = useState(0)
  const listRef = useRef<HTMLDivElement | null>(null)
  const viewport = 232 // 与 .fc-eventlist max-height 一致
  const first = virtual ? Math.max(0, Math.floor(scrollTop / (EV_ITEM_H + EV_GAP)) - EV_OVERSCAN) : 0
  const visibleCount = virtual ? Math.ceil(viewport / (EV_ITEM_H + EV_GAP)) + EV_OVERSCAN * 2 : events.length
  const last = Math.min(events.length, first + visibleCount)

  // 选中项在虚拟化模式下必须可见:程序化滚动到选中行(仅当选中项在可视区外)
  useEffect(() => {
    if (!virtual || !listRef.current) return
    const el = listRef.current
    const top = eventIndex * (EV_ITEM_H + EV_GAP)
    if (top < el.scrollTop) {
      el.scrollTop = top
    } else if (top + EV_ITEM_H > el.scrollTop + viewport) {
      el.scrollTop = top + EV_ITEM_H - viewport
    }
  }, [eventIndex, virtual])

  const renderBtn = (ev: CompareEventSummary, i: number) => (
    <button
      key={ev.id}
      type="button"
      role="tab"
      aria-selected={i === eventIndex}
      className={`fc-evbtn ${i === eventIndex ? 'active' : ''}`}
      onClick={() => onSelectEvent(i)}
    >
      <span className="fc-evbtn-no">{i + 1}</span>
      <span className="fc-evbtn-body">
        <span className="fc-evbtn-kind">
          {ev.kindLabel}
          {!ev.recovered && <em className="fc-evbtn-unrec">未恢复</em>}
        </span>
        <small>
          {ev.gapText ? `缺口 ${ev.gapText} · ` : ''}
          {ev.startTime.toFixed(3)}–{ev.endTime.toFixed(3)}s · {ev.severity}
        </small>
      </span>
    </button>
  )

  if (!virtual) {
    return (
      <div className="fc-eventlist" data-testid="fc-event-list" role="tablist" aria-label="检出的事件">
        {events.map(renderBtn)}
      </div>
    )
  }
  return (
    <div
      className="fc-eventlist"
      data-testid="fc-event-list"
      role="tablist"
      aria-label={`检出的事件(共 ${events.length} 条,仅渲染可视区)`}
      ref={listRef}
      onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
    >
      <div style={{ height: first * (EV_ITEM_H + EV_GAP), flex: 'none' }} aria-hidden />
      {events.slice(first, last).map((ev, k) => renderBtn(ev, first + k))}
      <div style={{ height: Math.max(0, (events.length - last) * (EV_ITEM_H + EV_GAP)), flex: 'none' }} aria-hidden />
    </div>
  )
}

/** 窄窗口检测(案例要求 <900px 双标签);无 matchMedia 环境(测试/SSR)视为宽屏 */
function useNarrowViewport(breakpoint = 900): boolean {
  const [narrow, setNarrow] = useState(() =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(`(max-width: ${breakpoint}px)`).matches
      : false,
  )
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia(`(max-width: ${breakpoint}px)`)
    const on = (): void => setNarrow(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [breakpoint])
  return narrow
}

const STAGE_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#10b981', '#ec4899', '#14b8a6', '#f97316']

/** 端点展示:截断过长的地址(host:port),中间省略 */
function endpointLabel(ep: string, max = 22): string {
  if (ep.length <= max) return ep
  return `${ep.slice(0, Math.max(6, max - 1))}…`
}

/** 恢复脉冲的持续时长(归一化时间轴占比) */
const PING_DUR = 0.07

/** 图层可见性(图例即开关):全部缺省可见 */
export interface SeqLayers {
  seen: boolean
  gap: boolean
  sack: boolean
  retx: boolean
  ack: boolean
  evt: boolean
}

const ALL_LAYERS_ON: SeqLayers = { seen: true, gap: true, sack: true, retx: true, ack: true, evt: true }

/** 缩放窗口字节范围 */
export interface ZoomRange {
  start: number
  end: number
}

/** 缩放/平移的基准轴(=未缩放的完整视图范围);与当前显示的(已缩放)轴分离 */
export interface BaseRange {
  min: number
  max: number
}

/**
 * 序列空间图形:SVG 渲染已见字节条/Gap/SACK/重传回补箭头/ACK 游标。
 *
 * 元素级分镜动画(plan M4「过程感」):GSAP 只补间播放时刻这一个数字(usePlayback),
 * 每个元素的登场由 `marks` 的登场时刻 + 当前时刻**声明式**推导 —— transform/opacity,
 * 零布局回流。`progressive=false`(静态模式/reduced-motion/未开始播放)直接渲染全部元素,
 * 信息与终态完全等价,满足审批约束 #4。导出以便对动画参数做元素级测试。
 *
 * M5 完整 SSV:`layers` 控制图层显隐(图例即开关);`zoomRange`/`onZoomRange`
 * 支持滚轮缩放与拖拽平移(状态归父层,本组件只发事件;无回调时忽略交互)。
 */
export function SeqSpaceGraphic({
  vm,
  playhead,
  progressive,
  seqSpaceOverride,
  label = '序列空间图形化',
  caption = '视图聚焦缺口邻域',
  layers = ALL_LAYERS_ON,
  zoomRange = null,
  onZoomRange,
  baseRange,
  showEventPins = true,
  onSelectPacket,
}: {
  vm: CompareViewModel
  playhead: number
  progressive: boolean
  /** 对向视图:用另一份序列空间数据渲染(无 marks/无动画,progressive=false) */
  seqSpaceOverride?: SeqSpaceView
  label?: string
  /** 轴说明后缀:事件方向=聚焦缺口邻域;对向=全景 */
  caption?: string
  /** 图层显隐(缺省全显) */
  layers?: SeqLayers
  /** 当前缩放窗口(null=整个轴) */
  zoomRange?: ZoomRange | null
  /** 滚轮/拖拽改变缩放窗口的回调;不传则不响应交互 */
  onZoomRange?: (next: ZoomRange | null) => void
  /**
   * 缩放/平移的基准轴(未缩放的完整范围)。必须与 sq(可能已缩放)分离:
   * 若以已缩放轴为基准,放大后想缩小时边界钳死在当前窗口内,永远缩不回去
   */
  baseRange?: BaseRange
  /** 是否渲染事件位置轨(对向静态视图无本事件证据链,传 false) */
  showEventPins?: boolean
  /** 点击事件轨图钉跳到对应报文;不传则图钉仅悬停提示 */
  onSelectPacket?: (n: number) => void
}) {
  const sq = seqSpaceOverride ?? vm.seqSpace
  const base = baseRange ?? { min: sq.axisMin, max: sq.axisMax }
  const marks = vm.marks
  const W = 720
  const H = 150
  const x = (v: number): number => ((v - sq.axisMin) / (sq.axisMax - sq.axisMin)) * (W - 16) + 8

  // 滚轮缩放(以指针位置为锚):React 的 onWheel 是 passive,必须原生监听才能 preventDefault。
  // 锚点/钳制一律以 base(未缩放的基准轴)为准 —— sq 只是当前显示(可能已缩放)的窗口
  const svgRef = useRef<SVGSVGElement | null>(null)
  const dragRef = useRef<{ pointerId: number; x: number; width: number } | null>(null)
  useEffect(() => {
    const svg = svgRef.current
    if (!svg || !onZoomRange) return
    const onWheel = (ev: WheelEvent): void => {
      ev.preventDefault()
      const rect = svg.getBoundingClientRect()
      const frac = rect.width > 0 ? (ev.clientX - rect.left) / rect.width : 0.5
      onZoomRange(wheelZoom(base.min, base.max, zoomRange, frac, ev.deltaY))
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [onZoomRange, zoomRange, base.min, base.max])

  // 拖拽平移:按屏幕像素位移换算字节位移,窗口钳制在基准轴内
  const panBy = useCallback(
    (dxPx: number, widthPx: number): void => {
      if (!onZoomRange || widthPx <= 0) return
      const cur = zoomRange ?? { start: base.min, end: base.max }
      const span = cur.end - cur.start
      const dBytes = -(dxPx / widthPx) * span
      const full = base.max - base.min
      if (span >= full) return // 未缩放时无可平移范围
      let s0 = cur.start + dBytes
      s0 = Math.min(Math.max(s0, base.min), base.max - span)
      onZoomRange({ start: s0, end: s0 + span })
    },
    [onZoomRange, zoomRange, base.min, base.max],
  )

// 时间轴映射:等分坐标 playhead -> 真实秒(命中所属阶段区间,阶段内按比例反解),
  // 再查 ACK 轨迹。与 viewModel 的 timeToBand 互为逆映射。
  const timeline = useMemo(() => {
    const st = vm.stages
    if (st.length === 0) return null
    return {
      toAbs: (): number => {
        const idx = Math.min(st.length - 1, Math.max(0, Math.floor(playhead * st.length)))
        const seg = st[Math.min(idx, st.length - 1)]
        const segSpan = seg.t1 - seg.t0
        const frac = segSpan > 0 ? (playhead - seg.t0) / segSpan : 0
        return seg.startTime + Math.min(1, Math.max(0, frac)) * (seg.endTime - seg.startTime)
      },
    }
  }, [playhead, vm.stages])
  const ackAt = useCallback(
    (absT: number): number | null => {
      let last: number | null = null
      for (const pt of sq.ackTrack) {
        if (pt.time <= absT) last = pt.ack
        else break
      }
      return last
    },
    [sq.ackTrack],
  )

  // 某元素的登场进度:无标记 / 非 progressive 时恒为完整可见
  // ---- 各元素动画参数 ----
  const gapPop = progressive && marks.gapRevealAt != null ? popIn(playhead, marks.gapRevealAt) : null
  const win = progressive ? marks.dupAckWindow : undefined
  const retxAt = progressive ? marks.retxDrawAt : undefined
  const retxP = retxAt != null ? windowProgress(playhead, retxAt, retxAt + 0.06) : 1
  const pingD = progressive && marks.recoverAt != null ? playhead - marks.recoverAt : Infinity

  const nSack = sq.sackBlocks.length

  return (
    <svg
      className={`fc-seqsvg${onZoomRange ? ' fc-seqsvg-zoomable' : ''}`}
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={label}
      data-testid="fc-seqspace"
      ref={svgRef}
      onPointerDown={(e) => {
        if (!onZoomRange) return
        dragRef.current = { pointerId: e.pointerId, x: e.clientX, width: svgRef.current?.getBoundingClientRect().width ?? 0 }
        e.currentTarget.setPointerCapture?.(e.pointerId)
      }}
      onPointerMove={(e) => {
        const d = dragRef.current
        if (!d || d.pointerId !== e.pointerId) return
        panBy(e.clientX - d.x, d.width)
        d.x = e.clientX
      }}
      onPointerUp={(e) => {
        if (dragRef.current?.pointerId === e.pointerId) dragRef.current = null
      }}
    >
      {/* 刻度轴(全量事实层,始终完整可见) */}
      <line x1={8} y1={H - 22} x2={W - 8} y2={H - 22} stroke="#cbd5e1" />
      {sq.ticks.map((t) => (
        <g key={t}>
          <line x1={x(t)} y1={H - 22} x2={x(t)} y2={H - 18} stroke="#cbd5e1" />
          <text x={x(t)} y={H - 6} textAnchor="middle" fontSize={10} fill="#64748b">
            {t}
          </text>
        </g>
      ))}
      {/* 已见字节条(事实层:整个抓包看见过的字节,不做过程隐藏) */}
      {layers.seen &&
        sq.seenRuns.map(([s, e], i) => (
          <rect key={`seen${i}`} x={x(s)} y={30} width={Math.max(x(e) - x(s), 1)} height={14} fill="#10b981" rx={2}>
            <title>{`已见字节 ${Math.round(s)}–${Math.round(e)}`}</title>
          </rect>
        ))}
      {/* Gap hatch:在缺口显露时刻弹跳登场(缩放过冲),此前不可见 */}
      {layers.gap &&
        sq.gaps.map(([s, e], i) => {
        const gx = x(s)
        const gw = Math.max(x(e) - x(s), 2)
        const style = gapPop
          ? ({ transform: `scale(${gapPop.scale})`, transformBox: 'fill-box', transformOrigin: 'center' } as React.CSSProperties)
          : undefined
        return (
          <rect
            key={`gap${i}`}
            data-testid={`fc-gap-${i}`}
            x={gx}
            y={30}
            width={gw}
            height={14}
            fill="url(#fc-hatch)"
            stroke="#ef4444"
            strokeDasharray="3 2"
            opacity={gapPop ? gapPop.opacity : 1}
            style={style}
          >
            <title>{`未收到 ${Math.round(s)}–${Math.round(e)}`}</title>
          </rect>
        )
      })}
      {/* SACK 块(紫色,与已见字节区分):对端报告已收到、但本抓包点未必见过的字节。
          在 Dup ACK 窗口内按块序逐块向右长出;无窗口标记时保守完整显示 */}
      {layers.sack &&
        sq.sackBlocks.map(([s, e], i) => {
        const target = Math.max(x(e) - x(s), 2)
        let wFrac = 1
        let op = 1
        if (win && nSack > 0) {
          const slice = (win[1] - win[0]) / nSack
          wFrac = windowProgress(playhead, win[0] + slice * i, win[0] + slice * i + slice * 0.7)
          op = 0.5 + 0.5 * wFrac
        }
        return (
          <rect
            key={`sack${i}`}
            x={x(s)}
            y={48}
            width={Math.max(target * wFrac, wFrac > 0 ? 1 : 0)}
            height={10}
            fill="#8b5cf6"
            opacity={op}
            rx={2}
          >
            <title>{`SACK(对端已收) ${Math.round(s)}–${Math.round(e)}`}</title>
          </rect>
        )
      })}
      {/* 行内说明(M5 用户反馈):第二行色块的含义直接写在图上,不再靠猜 */}
      {layers.sack && sq.sackBlocks.length > 0 && (
        <text x={W - 8} y={56} textAnchor="end" fontSize={9} fill="#7c3aed">
          对端已收(SACK)
        </text>
      )}
      {/* 区间标注(M4 用户反馈):每个区间下方简短标注它是什么(数据/未收到/SYN…);
          按像素宽度防拥挤:放不下或与上一个标注太近的跳过 */}
      {(() => {
        const out: React.ReactNode[] = []
        let lastEndX = -Infinity
        // 兜底空数组:热更新/内存缓存中旧构建的视图模型没有 rangeLabels 字段
        const ordered = [...(sq.rangeLabels ?? [])].sort((a, b) => a.start - b.start)
        for (const l of ordered) {
          if (l.kind === 'gap' && !layers.gap) continue
          if (l.kind === 'seen' && !layers.seen) continue
          const x0 = x(l.start)
          const x1 = x(l.end)
          const w = x1 - x0
          if (w < l.text.length * 11 + 6) continue // 放不下
          const cx = x0 + w / 2
          const halfText = (l.text.length * 11) / 2
          if (cx - halfText < lastEndX + 4) continue // 与上一个标注重叠
          out.push(
            <text
              key={`rl-${l.start}-${l.kind}`}
              x={cx}
              y={72}
              textAnchor="middle"
              fontSize={10}
              fill={l.kind === 'gap' ? '#b91c1c' : '#475569'}
            >
              {l.text}
            </text>,
          )
          lastEndX = cx + halfText
        }
        return out
      })()}
      {/* 重传回补箭头:自缺口末端向上画出(随播放推进),配标签淡入 */}
      {layers.retx && sq.retxArrow && (
        <g>
          <line
            x1={x(sq.retxArrow.seq)}
            y1={70}
            x2={x(sq.retxArrow.seq)}
            y2={70 - 24 * retxP}
            stroke="#ef4444"
            strokeWidth={2}
            markerEnd="url(#fc-arr)"
          />
          <text x={x(sq.retxArrow.seq) + 4} y={70} fontSize={10} fill="#ef4444" opacity={retxP}>
            重传回补
          </text>
        </g>
      )}
      {/* ACK 游标(播放持续推进)与恢复脉冲 */}
      {(() => {
        if (!layers.ack || !timeline || sq.ackTrack.length === 0) return null
        const absT = timeline.toAbs()
        const ackPos = ackAt(absT)
        if (ackPos == null) return null
        const cx = x(ackPos)
        const showPing = Number.isFinite(pingD) && pingD >= 0 && pingD <= PING_DUR
        return (
          <g>
            <line x1={cx} y1={92} x2={cx} y2={H - 22} stroke="#1d4ed8" strokeWidth={1.5} strokeDasharray="4 3" />
            <circle cx={cx} cy={92} r={5} fill="#1d4ed8" />
            {showPing && (
              <>
                <circle
                  cx={cx}
                  cy={92}
                  r={6 + 26 * (pingD / PING_DUR)}
                  fill="none"
                  stroke="#059669"
                  strokeWidth={2}
                  opacity={(1 - pingD / PING_DUR) * 0.8}
                />
                <text x={cx} y={84} textAnchor="middle" fontSize={10} fill="#059669" opacity={1 - pingD / PING_DUR}>
                  缺口闭合
                </text>
              </>
            )}
            <text x={cx} y={showPing ? 76 : 88} textAnchor="middle" fontSize={10} fill="#1d4ed8">
              累计确认 ACK {ackPos}
            </text>
          </g>
        )
      })()}
      {/* 事件位置轨(M5 用户反馈):把证据链报文按序列号位置排布在下方空白带,
          让"这个位置发生了什么"直接可读 —— 数据段=彩色短条,纯 ACK=三角刻度。
          颜色与阶段带一致;点击图钉跳到对应报文(定位问题);
          图例可整体开关。showEventPins=false(对向静态视图)不渲染 */}
      {layers.evt && showEventPins && vm.eventPins.length > 0 && (
        <g data-testid="fc-event-pins" className={onSelectPacket ? 'fc-pins-clickable' : undefined}>
          <line x1={8} y1={116} x2={W - 8} y2={116} stroke="#eef2f7" />
          {vm.eventPins.map((pin, i) => {
            const px = x(pin.seq)
            if (px < 2 || px > W - 2) return null // 缩放窗口外
            const color = SEQ_STAGE_COLORS[((pin.colorIndex % SEQ_STAGE_COLORS.length) + SEQ_STAGE_COLORS.length) % SEQ_STAGE_COLORS.length]
            const w = Math.max((pin.len > 0 ? x(Math.min(pin.seq + pin.len, sq.axisMax)) - px : 0), 3)
            const clickable = onSelectPacket != null
            const hit = {
              onClick: clickable ? () => onSelectPacket!(pin.packetNumber) : undefined,
              style: { cursor: clickable ? ('pointer' as const) : undefined },
            }
            return (
              <g key={`pin${i}`} {...hit}>
                {pin.kind === 'data' ? (
                  <rect x={px} y={106} width={w} height={7} fill={color} rx={1.5}>
                    <title>{`${pin.label} seq=${pin.seq}${pin.len ? ` len=${pin.len}` : ''}${clickable ? '(点击查看报文)' : ''}`}</title>
                  </rect>
                ) : (
                  <path d={`M${px - 4},112 L${px + 4},112 L${px},105 z`} fill={color}>
                    <title>{`${pin.label}${clickable ? '(点击查看报文)' : ''}`}</title>
                  </path>
                )}
                <text x={px} y={124} textAnchor="middle" fontSize={8.5} fill={color}>
                  {`#${pin.packetNumber}`}
                </text>
              </g>
            )
          })}
        </g>
      )}
      {/* 轴说明:这是字节序列号空间,不是时间轴(用户反馈易误读为进度条) */}
      <text x={8} y={16} fontSize={10} fill="#94a3b8">
        序列号空间(字节) · {caption}
      </text>
      <defs>
        <pattern id="fc-hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
          <rect width="6" height="6" fill="#fee2e2" />
          <line x1="0" y1="0" x2="0" y2="6" stroke="#ef4444" strokeWidth="2" />
        </pattern>
        <marker id="fc-arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 z" fill="#ef4444" />
        </marker>
      </defs>
    </svg>
  )
}

/** 外壳:空态判定 + 以 eventKey 重挂载内容区(切换事件即复位播放/阶段选中) */
export function FaultCompare(props: FaultCompareProps) {
  const { vm } = props
  if (!vm) {
    return (
      <div className="fc-page" data-testid="fault-compare-empty">
        <div className="fc-toolbar">
        <button type="button" className="btn" onClick={props.onBack} data-testid="fc-back">
          ← 返回时序视图
        </button>
      </div>
      <div className="fc-empty">
        <p>该会话未检出可解释的 TCP 事件,没有可对照的故障过程。</p>
      </div>
      </div>
    )
  }
  return <CompareContent key={props.eventKey ?? 'single'} {...props} vm={vm} />
}

function CompareContent({
  vm,
  onSelectPacket,
  onBack,
  events,
  eventIndex = 0,
  onSelectEvent,
  initialStageIndex,
  onExport,
  onExportEvidence,
  appImpacts,
  endpoints,
}: FaultCompareProps & { vm: CompareViewModel }) {
  const stageAt = useMemo(
    () => (t: number): number => {
      if (!vm || vm.stages.length === 0) return -1
      for (let i = vm.stages.length - 1; i >= 0; i--) {
        if (t >= vm.stages[i].t0) return i
      }
      return -1
    },
    [vm],
  )
  // 恢复位置:初始阶段下标 -> 阶段起点时刻(usePlayback 仅在挂载时读取一次)
  const initialTime = initialStageIndex != null ? (vm.stages[initialStageIndex]?.t0 ?? 0) : 0
  const pb = usePlayback(vm.stages, stageAt, initialTime)
  const [selectedStage, setSelectedStage] = useState<number | null>(null)
  // 窄窗双标签与序列空间方向切换(事件切换单键重挂载,状态随之复位)
  const narrow = useNarrowViewport()
  const [faultTab, setFaultTab] = useState<'fault' | 'ref'>('fault')
  const [viewSide, setViewSide] = useState<'event' | 'opp'>('event')
  // M5 完整 SSV:视图范围(缺口邻域/全景)、缩放窗口、图层显隐。
  // 切换方向/范围时复位缩放 —— 不同基准轴下的窗口没有延续意义。
  const [viewMode, setViewMode] = useState<'gap' | 'panorama'>('gap')
  const [zoom, setZoom] = useState<ZoomRange | null>(null)
  const [layers, setLayers] = useState<SeqLayers>(ALL_LAYERS_ON)

  const baseView =
    viewSide === 'opp' ? (vm.opposite?.view ?? vm.seqSpace) : viewMode === 'panorama' ? (vm.panorama ?? vm.seqSpace) : vm.seqSpace
  const shownView = useMemo(
    () => (zoom ? clipSeqSpaceView(baseView, zoom.start, zoom.end) : baseView),
    [baseView, zoom],
  )
  const zoomClamped = zoom != null && (zoom.start > baseView.axisMin + 1e-9 || zoom.end < baseView.axisMax - 1e-9)
  const stepZoom = (factor: number): void => {
    const next = zoomStep({ axisMin: baseView.axisMin, axisMax: baseView.axisMax }, zoom, factor)
    const full = baseView.axisMax - baseView.axisMin
    setZoom(next.end - next.start >= full - 1e-9 ? null : next)
  }
  const caption = viewSide === 'opp' ? '对向全景' : viewMode === 'panorama' ? '全景(该方向全部字节)' : '聚焦缺口邻域'

  const onKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case ' ':
        e.preventDefault()
        if (pb.phase === 'playing') pb.pause()
        else if (pb.phase === 'static') pb.overrideOnce()
        else pb.play()
        break
      case 'ArrowRight':
        e.preventDefault()
        pb.stepForward()
        break
      case 'ArrowLeft':
        e.preventDefault()
        pb.stepBack()
        break
      case 'Escape':
        e.preventDefault()
        pb.stop()
        break
      default:
        break
    }
  }

  const activeIdx = selectedStage ?? pb.activeStageIndex
  const active = activeIdx >= 0 ? vm.stages[activeIdx] : null
  const showSwitcher = !!events && events.length > 0 && !!onSelectEvent
  // 跳包随行上下文:当前事件 + 活动阶段(阶段粒度恢复,案例 openQuestion 裁定)
  const jumpCtx = (): JumpContext => ({ eventIndex, stageIndex: activeIdx })

  return (
    <div className="fc-page" data-testid="fault-compare" tabIndex={0} onKeyDown={onKeyDown}>
      <div className="fc-toolbar">
        <button type="button" className="btn" onClick={onBack} data-testid="fc-back">
          ← 返回时序视图
        </button>
        <span className="fc-headline">{vm.headline}</span>
        <span className="fc-phase">
          {phaseLabel(pb.phase)} {pb.phase === 'playing' || pb.phase === 'paused' ? `(${Math.round(pb.time * 100)}%)` : ''}
        </span>
        <span className="fc-controls">
          {onExport && (
            <button type="button" className="btn" onClick={onExport} data-testid="fc-export" title="导出当前事件为 Markdown 证据报告(不含正常参考示意)">
              导出报告
            </button>
          )}
          {onExportEvidence && (
            <button
              type="button"
              className="btn"
              onClick={onExportEvidence}
              data-testid="fc-export-evidence"
              title="导出当前事件为版本化 JSON 证据(pui-evidence schema,机器可读,与 Markdown 报告同口径)"
            >
              导出证据 JSON
            </button>
          )}
        </span>
        {pb.phase !== 'static' && (
          <span className="fc-controls">
            <button type="button" className="btn primary" onClick={pb.phase === 'playing' ? pb.pause : pb.play} data-testid="fc-playpause">
              {pb.phase === 'playing' ? '⏸ 暂停' : '▶ 播放'}
            </button>
            <button type="button" className="btn icon" onClick={pb.stepBack} aria-label="上一阶段">
              |◀
            </button>
            <button type="button" className="btn icon" onClick={pb.stepForward} aria-label="下一阶段">
              ▶|
            </button>
          </span>
        )}
        {pb.phase === 'static' && (
          <span className="fc-static-note" role="status">
            系统已开启「减少动效」,动画停用;可点选阶段或用单步遍历。
            <button type="button" className="btn" data-testid="fc-enable-animation" onClick={pb.overrideOnce}>
              仍要播放一次
            </button>
          </span>
        )}
      </div>

      {(vm.degraded.midStream || vm.degraded.unorderableInput || vm.degraded.lengthUnavailable) && (
        <div className="fc-degraded" role="status">
          {vm.degraded.midStream && <p>⚠ 抓包从连接中途开始:流起始处的缺失不构成丢包证据。</p>}
          {vm.degraded.lengthUnavailable && <p>⚠ 载荷长度不可用:相关字节数省略显示(绝不以 0 冒充)。</p>}
          {vm.degraded.unorderableInput && <p>⚠ 序列空间存在无法定位的输入:图形仅供参考。</p>}
        </div>
      )}

      <div className={narrow ? 'fc-body fc-body-narrow' : 'fc-body'}>
        {/* 窄窗口(<900px,案例要求):双标签切换,替代纵向长堆叠 */}
        {narrow && (
          <div className="seg fc-tabs" role="tablist" aria-label="对照视图切换" data-testid="fc-tabs">
            <button type="button" className={faultTab === 'fault' ? 'on' : ''} onClick={() => setFaultTab('fault')}>
              实际故障
            </button>
            <button type="button" className={faultTab === 'ref' ? 'on' : ''} onClick={() => setFaultTab('ref')}>
              正常参考
            </button>
          </div>
        )}

        {/* 左栏:实际故障 */}
        {(!narrow || faultTab === 'fault') && (
        <section className="fc-left" aria-label="实际故障">
          <h3>
            实际故障 <span className="fc-real-badge">真实抓包</span>
          </h3>

          {/* 事件切换器:VDI 实测单会话常有大量缺口事件,只看第一个不可用。
              事件数超 EV_VIRTUAL_THRESHOLD 时启用窗口虚拟化:只渲染可视区
              (每项固定高,按 scrollTop 换算),数千事件不再创建数千 DOM */}
          {showSwitcher && <EventSwitcher events={events!} eventIndex={eventIndex} onSelectEvent={onSelectEvent!} />}

          {/* 序列空间方向切换(M4:双向流对向视图)+ 视图范围/缩放(M5 完整 SSV)。
              方向按钮用「端点 → 端点」形态直观标注数据流向(传入 endpoints 时),
              否则退化为事件方向/对向;c2s/s2c 黑话仅保留在 title 里供对照 */}
          <div className="fc-dir-row">
            {vm.opposite && (
                <div className="seg" role="tablist" aria-label="序列空间方向" data-testid="fc-dir-toggle">
                  <button
                    type="button"
                    className={viewSide === 'event' ? 'on' : ''}
                    title={`数据方向 ${vm.direction}(报文从该方向发出)`}
                    onClick={() => {
                      setViewSide('event')
                      setZoom(null)
                    }}
                  >
                    {endpoints
                      ? vm.direction === 'c2s'
                        ? `${endpointLabel(endpoints.client)} → ${endpointLabel(endpoints.server)}`
                        : `${endpointLabel(endpoints.server)} → ${endpointLabel(endpoints.client)}`
                      : `事件方向(${vm.direction})`}
                  </button>
                  <button
                    type="button"
                    className={viewSide === 'opp' ? 'on' : ''}
                    title={`对向 ${vm.opposite.dir}(静态事实视图:无事件证据链)`}
                    onClick={() => {
                      setViewSide('opp')
                      setZoom(null)
                    }}
                  >
                    {endpoints
                      ? vm.opposite.dir === 'c2s'
                        ? `${endpointLabel(endpoints.client)} → ${endpointLabel(endpoints.server)}`
                        : `${endpointLabel(endpoints.server)} → ${endpointLabel(endpoints.client)}`
                      : `对向(${vm.opposite.dir})`}
                  </button>
                </div>
              )}
              {viewSide !== 'opp' && vm.panorama && (
                <div className="seg" role="tablist" aria-label="视图范围" data-testid="fc-mode-toggle">
                  <button
                    type="button"
                    className={viewMode === 'gap' ? 'on' : ''}
                    onClick={() => {
                      setViewMode('gap')
                      setZoom(null)
                    }}
                  >
                    缺口邻域
                  </button>
                  <button
                    type="button"
                    className={viewMode === 'panorama' ? 'on' : ''}
                    onClick={() => {
                      setViewMode('panorama')
                      setZoom(null)
                    }}
                  >
                    全景
                  </button>
                </div>
              )}
              <span className="fc-zoom-btns">
                <button
                  type="button"
                  className="btn icon"
                  data-testid="fc-zoom-in"
                  aria-label="放大"
                  title="放大"
                  onClick={() => stepZoom(1.6)}
                >
                  ＋
                </button>
                <button
                  type="button"
                  className="btn icon"
                  data-testid="fc-zoom-out"
                  aria-label="缩小"
                  title="缩小"
                  onClick={() => stepZoom(1 / 1.6)}
                >
                  －
                </button>
                <button
                  type="button"
                  className="btn sm"
                  data-testid="fc-zoom-reset"
                  disabled={!zoomClamped}
                  title="重置缩放"
                  onClick={() => setZoom(null)}
                >
                  重置
                </button>
              </span>
          </div>

          {/* 序列空间图例即图层开关(M5 完整 SSV 筛选):点击切换显隐;
              随当前视图取值:对向视图无重传箭头,图例不得提示不存在的图元 */}
          <div className="fc-seq-legend" data-testid="fc-seq-legend">
            <button
              type="button"
              className={`lg-item${layers.seen ? ' on' : ''}`}
              aria-pressed={layers.seen}
              data-testid="fc-layer-seen"
              title="点击显示/隐藏已见字节"
              onClick={() => setLayers((l) => ({ ...l, seen: !l.seen }))}
            >
              <i className="lg lg-seen" />
              已见字节
            </button>
            <button
              type="button"
              className={`lg-item${layers.gap ? ' on' : ''}`}
              aria-pressed={layers.gap}
              data-testid="fc-layer-gap"
              title="点击显示/隐藏未收到区间"
              onClick={() => setLayers((l) => ({ ...l, gap: !l.gap }))}
            >
              <i className="lg lg-gap" />
              未收到
            </button>
            <button
              type="button"
              className={`lg-item${layers.sack ? ' on' : ''}`}
              aria-pressed={layers.sack}
              data-testid="fc-layer-sack"
              title="点击显示/隐藏 SACK"
              onClick={() => setLayers((l) => ({ ...l, sack: !l.sack }))}
            >
              <i className="lg lg-sack" />
              SACK(对端报告已收)
            </button>
            {(viewSide === 'event' || !vm.opposite) && vm.seqSpace.retxArrow && (
              <button
                type="button"
                className={`lg-item${layers.retx ? ' on' : ''}`}
                aria-pressed={layers.retx}
                data-testid="fc-layer-retx"
                title="点击显示/隐藏重传回补箭头"
                onClick={() => setLayers((l) => ({ ...l, retx: !l.retx }))}
              >
                <i className="lg lg-retx" />
                重传回补
              </button>
            )}
            <button
              type="button"
              className={`lg-item${layers.ack ? ' on' : ''}`}
              aria-pressed={layers.ack}
              data-testid="fc-layer-ack"
              title="点击显示/隐藏累计确认游标"
              onClick={() => setLayers((l) => ({ ...l, ack: !l.ack }))}
            >
              <i className="lg lg-ack" />
              累计确认(ACK)
            </button>
            <button
              type="button"
              className={`lg-item${layers.evt ? ' on' : ''}`}
              aria-pressed={layers.evt}
              data-testid="fc-layer-evt"
              title="点击显示/隐藏下方的事件位置标注(证据链报文按序列号位置排布)"
              onClick={() => setLayers((l) => ({ ...l, evt: !l.evt }))}
            >
              <i className="lg lg-evt" />
              事件位置
            </button>
          </div>

          {/* 序列空间图形化:核心可视化(事件方向=分镜动画;对向=静态事实;静态模式信息等价)。
              shownView = 基准视图(缺口邻域/全景/对向)+ 缩放裁剪;baseRange 始终是未缩放基准,
              滚轮/拖拽以它为界 —— 否则放大后缩小被钳死在当前窗口内 */}
          {viewSide === 'event' || !vm.opposite ? (
            <SeqSpaceGraphic
              vm={vm}
              seqSpaceOverride={shownView}
              caption={caption}
              layers={layers}
              zoomRange={zoom}
              onZoomRange={setZoom}
              baseRange={{ min: baseView.axisMin, max: baseView.axisMax }}
              onSelectPacket={onSelectPacket ? (n) => onSelectPacket(n, jumpCtx()) : undefined}
              playhead={pb.time}
              progressive={pb.phase === 'playing' || pb.phase === 'paused' || pb.phase === 'done'}
            />
          ) : (
            <SeqSpaceGraphic
              vm={vm}
              seqSpaceOverride={shownView}
              label="对向序列空间"
              caption={caption}
              layers={layers}
              zoomRange={zoom}
              onZoomRange={setZoom}
              baseRange={{ min: baseView.axisMin, max: baseView.axisMax }}
              playhead={0}
              progressive={false}
              showEventPins={false}
            />
          )}

          {/* 阶段信息面板(固定,不依赖 hover) */}
          <div className="fc-stage-panel" data-testid="fc-stage-panel" role="region" aria-label="当前阶段信息">
            {active ? (
              <>
                <strong style={{ color: STAGE_COLORS[activeIdx % STAGE_COLORS.length] }}>
                  阶段 {activeIdx + 1}/{vm.stages.length}:{active.label}
                </strong>
                <span>
                  报文 #{active.fromPacket}–#{active.toPacket} · {active.startTime.toFixed(3)}–{active.endTime.toFixed(3)}s
                </span>
                <p>{active.summary}</p>
              </>
            ) : (
              <p>按「播放」或单步查看各故障阶段;阶段条上每个阶段始终可见。</p>
            )}
          </div>

          {/* 阶段带:上为 DSH duration 式总览条(彩色段+播放游标),下为阶段卡片
              (审批要求:每阶段的名称/起止包号/时刻/信息要点常驻可见,不藏在 hover 里) */}
          <div className="fc-timeband" data-testid="fc-stageband" role="list" aria-label="故障阶段时间带">
            <div className="fc-timeband-track">
              {vm.stages.map((s, i) => {
                const w = s.t1 - s.t0
                // 带内标注(常驻,不藏 hover):宽段显示「序号. 阶段名」,窄段退化为序号;
                // 完整信息(起止包号/时刻/要点)仍在下方阶段卡常驻
                const tag = w >= 0.12 ? `${i + 1}. ${s.label}` : w >= 0.03 ? `${i + 1}` : null
                return (
                  <div
                    key={`${s.label}-${s.fromPacket}`}
                    role="listitem"
                    tabIndex={0}
                    title={`阶段 ${i + 1}:${s.label}(#${s.fromPacket}–#${s.toPacket})`}
                    onClick={() => setSelectedStage(i)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') setSelectedStage(i)
                    }}
                    className={`fc-timeband-seg ${i === activeIdx ? 'active' : ''}`}
                    style={{
                      left: `${s.t0 * 100}%`,
                      width: `${Math.max(w * 100, 1.5)}%`,
                      background: STAGE_COLORS[i % STAGE_COLORS.length],
                    }}
                  >
                    {tag && <span className="fc-seg-tag">{tag}</span>}
                  </div>
                )
              })}
              {/* 游标=当前位置信息:idle(未开始)之外一律可见,静态模式同样信息等价 */}
              {pb.phase !== 'idle' && <div className="fc-timeband-cursor" style={{ left: `${pb.time * 100}%` }} />}
            </div>
            <div className="fc-stage-cards" data-testid="fc-stage-cards">
              {vm.stages.map((s, i) => (
                <button
                  key={`card-${s.label}-${i}`}
                  type="button"
                  className={`fc-stage-card ${i === activeIdx ? 'active' : ''}`}
                  onClick={() => setSelectedStage(i)}
                >
                  <span className="fc-stage-idx" style={{ background: STAGE_COLORS[i % STAGE_COLORS.length] }}>
                    {i + 1}
                  </span>
                  <span className="fc-stage-name">{s.label}</span>
                  <span className="fc-stage-pkt">
                    #{s.fromPacket}–#{s.toPacket} · {s.startTime.toFixed(3)}–{s.endTime.toFixed(3)}s
                  </span>
                  <p className="fc-stage-summary">{s.summary}</p>
                </button>
              ))}
            </div>
          </div>

          {/* 事件卡:观察/推断/限制三层 */}
          <div className="fc-card">
            <div className="fc-card-sec">
              <h4>观察 Observed</h4>
              <ul>
                {vm.card.observations.map((o, i) => (
                  <li key={i}>
                    <button type="button" className="fc-pkt-chip" onClick={() => onSelectPacket(o.packetNumber, jumpCtx())} title="查看报文详情">
                      #{o.packetNumber}
                    </button>
                    {o.statement}
                  </li>
                ))}
              </ul>
            </div>
            <div className="fc-card-sec">
              <h4>推断 Inference · 置信度 {vm.card.inference.confidence}</h4>
              <p>{vm.card.inference.statement}</p>
            </div>
            <div className="fc-card-sec fc-limitations">
              <h4>限制 Limitation</h4>
              <ul>
                {vm.card.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* 关键报文链(仅证据链报文) */}
          <div className="fc-keypkts" data-testid="fc-messages">
            <h4>关键报文链</h4>
            <div className="fc-keypkt-row">
              {vm.keyPackets.map((m) => (
                <button
                  key={m.packetNumber}
                  type="button"
                  className={`fc-keypkt ${m.stageIndex === activeIdx && (pb.phase !== 'idle' || selectedStage != null) ? 'now' : ''}`}
                  onClick={() => onSelectPacket(m.packetNumber, jumpCtx())}
                  title={m.label}
                >
                  {m.roleBadge && <span className="fc-keypkt-role">{m.roleBadge}</span>}#{m.packetNumber}
                </button>
              ))}
            </div>
          </div>

          {/* M6:同期应用层关联(时间窗重叠,限定措辞由 impact 层统一给出)。
              属实际故障侧观察,可跳到应用层报文;无关联(或未传)不渲染 */}
          {appImpacts != null && appImpacts.length > 0 && (
            <div className="fc-app-impacts" data-testid="fc-app-impacts">
              <h4>同期应用层事件(M6 时间窗关联)</h4>
              {appImpacts.map((imp) => (
                <button
                  key={`${imp.app.id}-${imp.tcp.id}`}
                  type="button"
                  className="fc-app-impact"
                  title={`${imp.app.summary} · #${imp.app.packetNumber}(点击跳到该报文)`}
                  onClick={() => onSelectPacket(imp.app.packetNumber, jumpCtx())}
                >
                  <span className="fc-app-impact-summary">{imp.app.summary}</span>
                  <small>{imp.statement}</small>
                </button>
              ))}
            </div>
          )}
        </section>
        )}

        {/* 右栏:正常参考(示意) */}
        {(!narrow || faultTab === 'ref') && (
        <section className="fc-right" aria-label="正常参考示意">
          <h3>
            正常参考 <span className="fc-ref-badge">示意 · 非本抓包数据</span>
          </h3>
          <ol className="fc-ref-steps" data-testid="fc-ref-steps">
            {vm.referenceSteps.map((r, i) => (
              <li key={i} className={`fc-ref-${r.kind}`}>
                <span className="fc-ref-stepno">{r.index}</span>
                <span>{r.label}</span>
                <small>{r.detail}</small>
              </li>
            ))}
          </ol>
          <p className="fc-ref-note">
            本栏为解释性基线:同类交互正常情况下应为连续发送、ACK 逐段前进。它不是本抓包中的真实报文,
            不进入任何观察、证据或导出报告。
          </p>
        </section>
        )}
      </div>
    </div>
  )
}
