import { useRef, useState } from 'react'
import { SequenceDiagram } from '../render/SequenceDiagram'
import { SeqSpaceTimeline } from '../render/SeqSpaceTimeline.tsx'
import { PacketDetail } from '../detail/PacketDetail'
import { ErrorBoundary } from './ErrorBoundary'
import { useApp, selectSelected } from '../state/appStore'
import { exportSvgPng, defaultPngName } from '../export/exportPng'

/**
 * 时序图整页板块(用户要求 2026-08-31):主视图右下角的时序图区域太小,
 * 长会话交互看不清 —— 本板块把时序图放到整页(与故障分析/双点对照同模式),
 * 下方保留报文详情联动(点报文看分层+hex),返回时主视图状态不受影响。
 *
 * diagramStyle/timeMode 与主视图共用 store(风格偏好延续);zoom 是画布
 * 观看尺度而非风格偏好,整页自管(主视图的 zoom 语义是"挤压布局",这里
 * 要的是"看大图",混用会互相干扰)。
 */
export function SequenceBoard({ onClose }: { onClose: () => void }) {
  const selected = useApp(selectSelected)
  const diagramStyle = useApp((s) => s.diagramStyle)
  const timeMode = useApp((s) => s.timeMode)
  const highlight = useApp((s) => s.highlight)
  const selectPacket = useApp((s) => s.selectPacket)
  const [zoom, setZoom] = useState(1)
  const svgRef = useRef<SVGSVGElement | null>(null)
  // 详情面板高度可拖拽(与主视图同一持久化键族,但独立值 —— 整页空间不同,默认更高)
  const DETAIL_KEY = 'pui:seqBoardDetailHeight'
  const [detailHeight, setDetailHeight] = useState(() => {
    const v = Number(localStorage.getItem(DETAIL_KEY))
    return Number.isFinite(v) && v > 0 ? v : 320
  })
  const startDrag = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    const el = e.currentTarget
    el.setPointerCapture(e.pointerId)
    const startY = e.clientY
    const startH = detailHeight
    const move = (ev: globalThis.PointerEvent) => {
      // 详情在下方:向上拖(减少 y)= 详情变高
      const next = Math.min(720, Math.max(120, startH - (ev.clientY - startY)))
      setDetailHeight(next)
      localStorage.setItem(DETAIL_KEY, String(next))
    }
    const cleanup = () => {
      el.removeEventListener('pointermove', move)
      el.removeEventListener('pointerup', cleanup)
      el.removeEventListener('pointercancel', cleanup)
    }
    el.addEventListener('pointermove', move)
    el.addEventListener('pointerup', cleanup)
    el.addEventListener('pointercancel', cleanup)
  }

  const onExport = async () => {
    if (!selected) return
    try {
      await exportSvgPng(svgRef.current, defaultPngName(selected.client, selected.server, selected.protocol))
    } catch (err) {
      window.alert(err instanceof Error ? err.message : String(err))
    }
  }

  if (!selected) {
    return (
      <div className="dc-page" data-testid="seq-board-empty">
        <div className="dc-toolbar">
          <span className="dc-headline">⇄ 时序图</span>
          <button type="button" className="btn" onClick={onClose} data-testid="seq-board-back">
            ← 返回
          </button>
        </div>
        <div className="dc-empty">
          <p>未选中会话:回到主视图选择一个会话后再进入整页时序图。</p>
        </div>
      </div>
    )
  }

  return (
    <div className="dc-page" data-testid="seq-board">
      <div className="dc-toolbar">
        <span className="dc-headline">⇄ 时序图 · {selected.client} ⇄ {selected.server}</span>
        <button type="button" className="btn" onClick={onClose} data-testid="seq-board-back">
          ← 返回
        </button>
        <span className="dc-bmeta">
          {selected.packetCount.toLocaleString()} 包 · 报文点击后下方显示分层详情
        </span>
        <span style={{ flex: 1 }} />
        {/* 画布缩放(整页自管,与主视图 zoom 语义无关):+/− 步进 10%,50%~300% */}
        <button type="button" className="btn icon" onClick={() => setZoom((z) => Math.max(0.5, Math.round((z - 0.1) * 10) / 10))} title="缩小" data-testid="seq-board-zoom-out">
          −
        </button>
        <span className="dc-bmeta">{Math.round(zoom * 100)}%</span>
        <button type="button" className="btn icon" onClick={() => setZoom((z) => Math.min(3, Math.round((z + 0.1) * 10) / 10))} title="放大" data-testid="seq-board-zoom-in">
          +
        </button>
        <button type="button" className="btn" onClick={onExport} data-testid="seq-board-export">
          导出 PNG
        </button>
      </div>

      {/* 时序图主体:占据剩余全部空间(整页价值所在);内部滚动,放大后同样可达 */}
      <div className="seq-board-canvas" data-testid="seq-board-canvas">
        <ErrorBoundary name="时序图(整页)">
          {diagramStyle === 'C' ? (
            <SeqSpaceTimeline
              conv={selected}
              highlight={highlight}
              onSelect={(n) => selectPacket(n)}
              svgRef={svgRef}
              zoom={zoom}
            />
          ) : (
            <SequenceDiagram
              conv={selected}
              style={diagramStyle}
              timeMode={timeMode}
              highlight={highlight}
              onSelect={(n) => selectPacket(n)}
              svgRef={svgRef}
              zoom={zoom}
            />
          )}
        </ErrorBoundary>
      </div>

      {/* 拖拽分隔条:向上拖增高详情区(与主视图 h-resizer 同交互) */}
      <div className="h-resizer" onPointerDown={startDrag} title="拖动调整详情高度" />

      <div style={{ height: detailHeight, flex: 'none', overflow: 'hidden' }}>
        <ErrorBoundary name="报文详情(时序图整页)">
          <PacketDetail />
        </ErrorBoundary>
      </div>
    </div>
  )
}
