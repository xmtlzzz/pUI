import { useEffect, useMemo, useRef, useState, type DragEvent, type PointerEvent } from 'react'
import { Toolbar } from './Toolbar'
import { FilterPanel } from './FilterPanel'
import { ListPane } from './ListPane'
import { ErrorBoundary } from './ErrorBoundary'
import { SequenceDiagram } from '../render/SequenceDiagram'
import { PacketDetail } from '../detail/PacketDetail'
import { FaultCompare } from './FaultCompare'
import { useApp, selectSelected } from '../state/appStore'
import { isTauri } from '../bridge/tauri'
import { exportSvgPng, defaultPngName } from '../export/exportPng'
import { exportTranscript } from '../export/exportTranscript'
import { saveText } from '../bridge/tauri'
import { analyzeStream } from '../analysis/tcp/streamAnalysis'
import { detectTcpEvents } from '../analysis/tcp/events'
import { deriveStages } from '../analysis/tcp/stages'
import { buildCompareViewModel } from '../m4/viewModel'

function clamp(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v))
}

export function AppLayout() {
  const openFile = useApp((s) => s.openFile)
  const error = useApp((s) => s.error)
  const selected = useApp((s) => selectSelected(s))
  const diagramStyle = useApp((s) => s.diagramStyle)
  const timeMode = useApp((s) => s.timeMode)
  const highlight = useApp((s) => s.highlight)
  const selectPacket = useApp((s) => s.selectPacket)
  const compareFor = useApp((s) => s.compareFor)
  const openCompare = useApp((s) => s.openCompare)
  const closeCompare = useApp((s) => s.closeCompare)
  const [drag, setDrag] = useState(false)
  const [zoom, setZoom] = useState(1)
  const svgRef = useRef<SVGSVGElement | null>(null)

  // M4 对照页数据:按需从当前选中会话派生(引擎是纯函数,重算成本低,不入 store)。
  // 无事件时 vm 为 null,FaultCompare 自行渲染空态。
  const compareVm = useMemo(() => {
    if (!compareFor || !selected || selected.id !== compareFor) return null
    const facts = analyzeStream(selected.packets)
    const events = detectTcpEvents(facts, selected.packets)
    const event = events[0]
    if (!event) return null
    const stages = deriveStages(event, facts, selected.packets)
    return buildCompareViewModel(selected.packets, facts, event, stages)
  }, [compareFor, selected])

  // 可拖拽尺寸:会话列表宽度(左/右)、报文详情高度(上/下);持久化,拖一次即记住
  const LS_LIST = 'pui:listWidth'
  const LS_DETAIL = 'pui:detailHeight'
  const loadNum = (key: string, fallback: number): number => {
    const v = Number(localStorage.getItem(key))
    return Number.isFinite(v) && v > 0 ? v : fallback
  }
  // 载入时即按当前窗口钳制,防止在大屏存下的尺寸在小屏上压没时序图
  const [listWidth, setListWidth] = useState(() => clamp(loadNum(LS_LIST, 380), 220, 720))
  const [detailHeight, setDetailHeight] = useState(() => clamp(loadNum(LS_DETAIL, 240), 90, Math.max(90, window.innerHeight - 220)))
  // 窗口尺寸运行中变化时,把持久化的面板尺寸重新钳制到当前窗口内(避免压没时序图)
  useEffect(() => {
    const onResize = () => {
      setListWidth((w) => clamp(w, 220, 720))
      setDetailHeight((h) => clamp(h, 90, Math.max(90, window.innerHeight - 220)))
    }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  const listRef = useRef(listWidth)
  const detailRef = useRef(detailHeight)
  useEffect(() => {
    localStorage.setItem(LS_LIST, String(listWidth))
  }, [listWidth])
  useEffect(() => {
    localStorage.setItem(LS_DETAIL, String(detailHeight))
  }, [detailHeight])

  const onExport = async () => {
    if (!selected) return
    try {
      await exportSvgPng(svgRef.current, defaultPngName(selected.client, selected.server, selected.protocol))
    } catch (err) {
      // 导出失败(如会话过大超上限):把原因展示给用户,而非静默失败
      window.alert(err instanceof Error ? err.message : String(err))
    }
  }

  const onExportText = async () => {
    if (!selected) return
    try {
      const md = exportTranscript(selected)
      const name = defaultPngName(selected.client, selected.server, selected.protocol).replace(/\.png$/i, '.md')
      await saveText(name, md)
    } catch (err) {
      window.alert(err instanceof Error ? err.message : String(err))
    }
  }

  // 可拖拽尺寸:用 pointer capture 挂在分隔条上,拖出窗口也不泄漏监听;
  // 额外监听 window blur,失焦时兜底清理
  const makeDrag =
    (axis: 'x' | 'y', min: number, max: () => number) => (e: PointerEvent<HTMLDivElement>) => {
      e.preventDefault()
      const el = e.currentTarget
      el.setPointerCapture(e.pointerId)
      const start = axis === 'x' ? e.clientX : e.clientY
      const initial = axis === 'x' ? listRef.current : detailRef.current
      const setVal = axis === 'x' ? setListWidth : setDetailHeight
      const setRef = axis === 'x' ? (v: number) => (listRef.current = v) : (v: number) => (detailRef.current = v)

      const move = (ev: globalThis.PointerEvent) => {
        const delta = axis === 'x' ? ev.clientX - start : start - ev.clientY
        const v = clamp(initial + delta, min, max())
        setRef(v)
        setVal(v)
      }
      const cleanup = () => {
        el.removeEventListener('pointermove', move)
        el.removeEventListener('pointerup', cleanup)
        el.removeEventListener('pointercancel', cleanup)
        window.removeEventListener('blur', cleanup)
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
      }
      el.addEventListener('pointermove', move)
      el.addEventListener('pointerup', cleanup)
      el.addEventListener('pointercancel', cleanup)
      window.addEventListener('blur', cleanup)
      document.body.style.cursor = axis === 'x' ? 'col-resize' : 'row-resize'
      document.body.style.userSelect = 'none'
    }
  const startVDrag = makeDrag('x', 220, () => 720)
  const startHDrag = makeDrag('y', 90, () => Math.max(90, window.innerHeight - 220))

  // Tauri 2:拖拽文件须用窗口 onDragDropEvent 才能拿到真实路径
  useEffect(() => {
    if (!isTauri()) return
    let active = true
    let unlisten: (() => void) | undefined
    import('@tauri-apps/api/window')
      .then(({ getCurrentWindow }) =>
        getCurrentWindow().onDragDropEvent((e) => {
          if (e.payload.type === 'over') setDrag(true)
          else if (e.payload.type === 'leave') setDrag(false)
          else if (e.payload.type === 'drop') {
            setDrag(false)
            const p = e.payload.paths[0]
            if (p) openFile(p)
          }
        }),
      )
      .then((f) => {
        if (!active) {
          f() // StrictMode 首次挂载已卸载,立即反注册,避免重复监听
          return
        }
        unlisten = f
      })
    return () => {
      active = false
      unlisten?.()
    }
  }, [openFile])

  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setDrag(false)
    if (isTauri()) return // Tauri 模式由 onDragDropEvent 处理
    const f = e.dataTransfer.files?.[0]
    if (f) openFile(f.name)
  }

  return (
    <div
      className="app"
      onDragOver={(e) => {
        e.preventDefault()
        if (!isTauri()) setDrag(true)
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
    >
      {/* M4 整页板块:进入故障分析时整个工作区切换(用户要求,替代右侧面板局部替换)。
          顶部工具条保留(打开文件/导出仍可用),筛选/列表/时序/详情全部让位。 */}
      {compareFor ? (
        <>
          <Toolbar zoom={zoom} setZoom={setZoom} onExport={onExport} onExportText={onExportText} hasConversation={!!selected} />
          {error && <div className="err">{error}</div>}
          <ErrorBoundary name="故障分析">
            <FaultCompare
              vm={compareVm}
              onSelectPacket={(n) => {
                // 跳回原报文:退出对照板块回到主视图并定位报文详情
                closeCompare()
                selectPacket(n)
              }}
              onBack={closeCompare}
            />
          </ErrorBoundary>
        </>
      ) : (
        <>
          <Toolbar zoom={zoom} setZoom={setZoom} onExport={onExport} onExportText={onExportText} hasConversation={!!selected} />
          {error && <div className="err">{error}</div>}
          {selected && (
            <div style={{ padding: '4px 12px 0' }}>
              <button type="button" onClick={() => openCompare(selected.id)} data-testid="fault-analyze-entry">
                ⚠ 故障分析(对照正常参考)
              </button>
            </div>
          )}
          <div className="body">
            <div className="pane filter">
              <FilterPanel />
            </div>
            <div className="pane list" style={{ width: listWidth }}>
              <ErrorBoundary name="会话列表">
                <ListPane />
              </ErrorBoundary>
            </div>
            <div className="v-resizer" onPointerDown={startVDrag} title="拖动调整宽度" />
            <div className="pane view">
              <ErrorBoundary name="时序图">
                <SequenceDiagram conv={selected} style={diagramStyle} timeMode={timeMode} highlight={highlight} onSelect={selectPacket} svgRef={svgRef} zoom={zoom} />
              </ErrorBoundary>
              <div className="h-resizer" onPointerDown={startHDrag} title="拖动调整高度" />
              <div style={{ height: detailHeight, flex: 'none', overflow: 'hidden' }}>
                <ErrorBoundary name="报文详情">
                  <PacketDetail />
                </ErrorBoundary>
              </div>
            </div>
          </div>
        </>
      )}
      {drag && <div className="drop-zone">松开以打开抓包文件</div>}
    </div>
  )
}
