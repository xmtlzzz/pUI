import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import {
  computeFlowLayout,
  FLOW_CLIENT_X,
  FLOW_SERVER_X,
  FLOW_HEADER_H,
  TIME_COL_X,
  type FlowLayoutOptions,
} from './flowTimeline.ts' // 显式扩展名:与 FlowTimeline.tsx 仅大小写之差,无扩展名在 Win 大小写不敏感盘上会解析到本文件自身
import { protocolColor } from '../model/protocolColors'
import { formatEpoch } from './timeFormat'
import type { Conversation } from '../model/types'

/**
 * 「时间流」形态时序图(用户要求 2026-09-01:不要 A↔B 对角线,
 * 要一条时间轴、报文按时间从上往下排列、左侧时间节点的形式,类似
 * tcp 故障分析里的时间轴流画法)。
 *
 * 结构:左侧时间刻度列 + 两条垂直生命线(左=客户端/右=服务端)+
 * 每报文一行水平箭头(发送方圆点 → 接收方生命线)。布局逻辑全部在
 * flowTimeline.ts 纯函数中,本组件只做 SVG 映射。
 *
 * Props 与 SequenceDiagram 对齐(conv/highlight/onSelect/svgRef/zoom),
 * 方便 AppLayout/SequenceBoard 按 diagramStyle==='C' 一行三元切换。
 * 分段导航(segmentConversation)由父层负责;组件只兜底 2000 行 DOM 上限。
 */
export interface FlowTimelineProps {
  conv: Conversation | null
  highlight?: readonly number[]
  onSelect: (n: number) => void
  svgRef: RefObject<SVGSVGElement | null>
  /** 盒尺寸缩放:乘 width/height(盒尺寸模式与 SequenceDiagram 一致,
   *  否则滚动容器按原始尺寸算,放大后下半图永远滚不到) */
  zoom: number
  /** 刻度抽稀密度(透传 computeFlowLayout);缺省全量,由布局函数决定 */
  tickEvery?: number
}

/** 方向色:与 SequenceDiagram 的请求/响应/其他三色一致(全局色板不另起炉灶) */
const DIR_COLOR: Record<string, string> = { a2b: '#3b82f6', b2a: '#f97316', neutral: '#94a3b8' }
const DIR_LABEL: Record<string, string> = { a2b: '请求', b2a: '响应', neutral: '其他' }

export function FlowTimeline({ conv, highlight, onSelect, svgRef, zoom, tickEvery }: FlowTimelineProps) {
  // 布局只在会话/密度变化时重算:zoom、highlight、选中等变化不再全量重排
  const layout = useMemo(() => {
    const opts: FlowLayoutOptions = { client: conv?.client ?? '' }
    if (conv?.server) opts.server = conv.server
    if (tickEvery != null) opts.tickEvery = tickEvery
    return computeFlowLayout(conv ? conv.packets : [], opts)
  }, [conv, tickEvery])
  // 高亮集合:O(行数·k) 的数组扫描转 O(1) 命中(同 SequenceDiagram 注释)
  const hlSet = useMemo(() => (highlight ? new Set(highlight) : null), [highlight])

  // 占满容器宽度(2026-09-02 用户要求,C 形态同款):viewBox 宽跟随容器实际
  // 宽度(布局 520 只是下限),ResizeObserver 监听;jsdom 无布局,window
  // resize + 测试钩子兜底。生命线 x 按宽度比例放置,加宽时两线拉开距离。
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
    window.addEventListener('resize', measure)
    ;(window as unknown as { __flowResize?: () => void }).__flowResize = measure
    return () => {
      window.removeEventListener('resize', measure)
      delete (window as unknown as { __flowResize?: () => void }).__flowResize
    }
  }, [])

  if (!conv) {
    // 与 SequenceDiagram 相同的空态文案:两个组件切换时用户感知一致
    return <div className="empty">从左侧选择一个会话查看时序图</div>
  }

  // 画布宽与生命线位置:容器更宽时按比例拉开生命线(比例同 520 基准 110/470),
  // 时间列与箭头文字都跟随;高度不变(纵向滚动)。
  // client/server 都按 layout.width 等比 —— 此前 serverX 用「固定距右缘」,
  // 加宽时只拉 client 端、server 端不动,中线右偏(审计 L2)
  const width = Math.max(layout.width, wrapWidth)
  const clientX = Math.round((FLOW_CLIENT_X / layout.width) * width)
  const serverX = Math.round((FLOW_SERVER_X / layout.width) * width)

  const yOf = (i: number) => layout.rows[i].y

  return (
    <div ref={wrapRef} className="seq-wrap" style={{ flex: 1, overflow: 'auto', position: 'relative', background: '#f8fafc', border: '1px solid #eef2f7', borderRadius: 8, padding: 8 }}>
      {conv.issues.length > 0 && (
        <div className="issue-banner">⚠ {conv.issues.map((i) => i.message).join('；')}</div>
      )}
      {layout.truncated && (
        <div className="many-warn" style={{ margin: '2px 0 4px' }}>
          报文较多:已截断显示 {layout.rows.length}/{layout.total} 条(DOM 上限),建议分段查看
        </div>
      )}
      <svg
        ref={svgRef}
        data-testid="flow-timeline"
        width={width * zoom}
        height={layout.height * zoom}
        viewBox={`0 0 ${width} ${layout.height}`}
        style={{ display: 'block', font: '11px system-ui, sans-serif' }}
      >
        {/* 顶部端点标签:左=客户端,右=服务端(生命线顶端) */}
        <text x={clientX} y={FLOW_HEADER_H - 14} textAnchor="middle" fill="#1d4ed8" fontWeight="bold">
          {conv.client}
        </text>
        <text x={serverX} y={FLOW_HEADER_H - 14} textAnchor="middle" fill="#c2410c" fontWeight="bold">
          {conv.server}
        </text>
        {/* 两条垂直生命线:贯穿全图,报文在其间水平流动 */}
        <line x1={clientX} y1={FLOW_HEADER_H} x2={clientX} y2={layout.height - 8} stroke="#cbd5e1" strokeDasharray="4 4" />
        <line x1={serverX} y1={FLOW_HEADER_H} x2={serverX} y2={layout.height - 8} stroke="#cbd5e1" strokeDasharray="4 4" />

        {layout.rows.map((r, i) => {
          const isHit = hlSet?.has(r.number) ?? false
          // 行底色:异常行浅红(观察层强调 ≠ 结论);命中高亮行用浅蓝区分
          const rowBg = isHit ? '#dbeafe' : r.anomaly ? '#fee2e2' : 'transparent'
          const stroke = r.anomaly ? '#ea580c' : protocolColor(r.proto)
          const x1 = r.dir === 'b2a' ? serverX : clientX
          const x2 = r.dir === 'b2a' ? clientX : serverX
          const y = yOf(i)
          return (
            <g
              key={r.number}
              className={`flow-row ${r.dir}${r.anomaly ? ' anomaly' : ''}${isHit ? ' hl' : ''}`}
              style={{ cursor: 'pointer' }}
              onClick={() => onSelect(r.number)}
            >
              {/* 行底带:覆盖整行宽度,异常/高亮视觉强调的主体 */}
              <rect x={2} y={y - layout.rowHeight / 2} width={width - 4} height={layout.rowHeight} fill={rowBg} rx={3}>
                <title>{`${DIR_LABEL[r.dir]} · ${r.label}${r.anomaly ? ' · ⚠ tcp分析标记' : ''}`}</title>
              </rect>
              {/* 中性方向:画短横线(两端都不确定,不指令断言方向) */}
              {r.dir === 'neutral' ? (
                <line x1={clientX + 20} y1={y} x2={serverX - 20} y2={y} stroke={stroke} strokeWidth={1.6} strokeDasharray="2 3" />
              ) : (
                <>
                  {/* 发送方圆点:报文从这条生命线发出 */}
                  <circle cx={x1} cy={y} r={3.5} fill={DIR_COLOR[r.dir]} stroke="#fff" strokeWidth={1}>
                    <title>{DIR_LABEL[r.dir]}</title>
                  </circle>
                  {/* 水平箭头:请求向右,响应向左 */}
                  <line x1={x1 + 6} y1={y} x2={x2 - 7} y2={y} stroke={stroke} strokeWidth={1.6} markerEnd="url(#flow-arr)" />
                </>
              )}
              {/* 左侧时间刻度:该包时刻(时间节点列);右对齐基准与布局层 TIME_COL_X 同源(审计 L5 常量统一) */}
              <text x={TIME_COL_X} y={y + 3} textAnchor="end" fill={r.anomaly ? '#ea580c' : '#64748b'} fontSize={9} style={{ fontVariantNumeric: 'tabular-nums' }}>
                {r.timeEpoch != null && r.timeEpoch > 0 ? `${formatEpoch(r.timeEpoch)}` : r.timeLabel}
              </text>
              {/* 行内标注:#帧号 协议概要 · 长度 */}
              <text className="flow-label" x={(clientX + serverX) / 2} y={y + 3.5} textAnchor="middle" fill={stroke} fontSize={10}>
                {r.label}
              </text>
            </g>
          )
        })}
        <defs>
          <marker id="flow-arr" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
            <path d="M0,0 L7,3 L0,6 z" fill="#475569" />
          </marker>
        </defs>
      </svg>
    </div>
  )
}
