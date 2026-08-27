import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type PointerEvent } from 'react'
import { Toolbar } from './Toolbar'
import { FilterPanel } from './FilterPanel'
import { ListPane } from './ListPane'
import { ErrorBoundary } from './ErrorBoundary'
import { SequenceDiagram } from '../render/SequenceDiagram'
import { PacketDetail } from '../detail/PacketDetail'
import { FaultCompare } from './FaultCompare'
import { useApp, selectSelected } from '../state/appStore'
import type { CompareResume } from '../state/appStore'
import { isTauri } from '../bridge/tauri'
import { exportSvgPng, defaultPngName } from '../export/exportPng'
import { exportTranscript } from '../export/exportTranscript'
import { exportCompareReport, defaultCompareReportName } from '../export/exportCompareReport'
import { saveText } from '../bridge/tauri'
import { analyzeStream } from '../analysis/tcp/streamAnalysis'
import { detectTcpEvents } from '../analysis/tcp/events'
import { deriveStages } from '../analysis/tcp/stages'
import { buildCompareViewModel, buildEventSummaries, type CompareViewModel } from '../m4/viewModel'
import type { TcpEvent } from '../analysis/tcp/events'

function clamp(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v))
}

export function AppLayout() {
  const openFile = useApp((s) => s.openFile)
  const error = useApp((s) => s.error)
  const meta = useApp((s) => s.meta)
  const currentPath = useApp((s) => s.currentPath)
  const selected = useApp((s) => selectSelected(s))
  const diagramStyle = useApp((s) => s.diagramStyle)
  const timeMode = useApp((s) => s.timeMode)
  const highlight = useApp((s) => s.highlight)
  const selectPacket = useApp((s) => s.selectPacket)
  const compareFor = useApp((s) => s.compareFor)
  const compareEventIndex = useApp((s) => s.compareEventIndex)
  const setCompareEventIndex = useApp((s) => s.setCompareEventIndex)
  const compareResume = useApp((s) => s.compareResume)
  const jumpFromCompare = useApp((s) => s.jumpFromCompare)
  const consumeCompareResume = useApp((s) => s.consumeCompareResume)
  const openCompare = useApp((s) => s.openCompare)
  const closeCompare = useApp((s) => s.closeCompare)
  const [drag, setDrag] = useState(false)
  const [zoom, setZoom] = useState(1)
  const svgRef = useRef<SVGSVGElement | null>(null)

  // M4 对照页数据:按需从当前选中会话派生(引擎是纯函数,重算成本低,不入 store)。
  // 卡顿修复(用户反馈 2026-08-27):VDI 2.3 万报文上 analyzeStream+detectTcpEvents 约
  // 数百毫秒,此前每次切换事件都全量重跑。会话级结果(facts/事件表/摘要)缓存于 ref,
  // 事件级 vm 按 event id 缓存 —— 切换事件只剩 deriveStages+投影(毫秒级)。
  const compareCacheRef = useRef<{
    id: string
    fingerprint: number
    facts: ReturnType<typeof analyzeStream>
    events: TcpEvent[]
    summaries: ReturnType<typeof buildEventSummaries>
    vmCache: Map<string, CompareViewModel | null>
  } | null>(null)
  const compare = useMemo(() => {
    if (!compareFor || !selected || selected.id !== compareFor) return null
    // 指纹防同 id 不同内容(重开同名抓包):首包时刻+包数+末包时刻
    const fingerprint =
      selected.packets.length > 0
        ? selected.packets.length * 1e9 + selected.packets[0].time * 1e3 + selected.packets[selected.packets.length - 1].time
        : 0
    let base = compareCacheRef.current
    if (!base || base.id !== selected.id || base.fingerprint !== fingerprint) {
      const facts = analyzeStream(selected.packets)
      const events: TcpEvent[] = detectTcpEvents(facts, selected.packets)
      base = { id: selected.id, fingerprint, facts, events, summaries: buildEventSummaries(events), vmCache: new Map() }
      compareCacheRef.current = base
    }
    if (base.events.length === 0) return { summaries: base.summaries, eventIndex: -1, vm: null }
    const idx = Math.min(Math.max(compareEventIndex, 0), base.events.length - 1)
    const eid = base.events[idx].id
    if (!base.vmCache.has(eid)) {
      // 防御 VDI 数百事件场景:vm 缓存有界(超过 64 条整体清空,重算也只是毫秒级投影)
      if (base.vmCache.size > 64) base.vmCache.clear()
      const stages = deriveStages(base.events[idx], base.facts, selected.packets)
      base.vmCache.set(eid, buildCompareViewModel(selected.packets, base.facts, base.events[idx], stages))
    }
    return { summaries: base.summaries, eventIndex: idx, vm: base.vmCache.get(eid)! }
  }, [compareFor, selected, compareEventIndex])
  const compareVm = compare?.vm ?? null

  // 跳包后返回恢复(case 审批裁定按分镜/阶段粒度):pendingResume 保存一次性初始阶段,
  // FaultCompare 挂载时读取;退出对照页时清除,避免下次正常进入误恢复。
  const [pendingResume, setPendingResume] = useState<CompareResume | null>(null)
  const exitCompare = useCallback(() => {
    closeCompare()
    setPendingResume(null)
  }, [closeCompare])

  // 对照页点跳包:记录(事件+阶段)→ 退回主视图并定位报文详情
  const jumpToPacket = useCallback(
    (n: number, ctx?: { eventIndex: number; stageIndex: number }) => {
      if (ctx && compare && compare.eventIndex >= 0) {
        jumpFromCompare({ conversationId: selected!.id, eventIndex: ctx.eventIndex, stageIndex: ctx.stageIndex })
      }
      setPendingResume(null)
      closeCompare()
      selectPacket(n)
    },
    [closeCompare, compare, jumpFromCompare, selectPacket, selected],
  )

  // 报文详情侧「返回故障分析」:消费 resume 恢复事件与阶段
  const resumeFaultAnalysis = useCallback(() => {
    const r = consumeCompareResume()
    if (!r || !selected || selected.id !== r.conversationId) return
    setCompareEventIndex(r.eventIndex)
    setPendingResume(r)
    openCompare(r.conversationId)
  }, [consumeCompareResume, openCompare, selected, setCompareEventIndex])

  // 报文详情「查看事件上下文」入口:点击时惰性分析当前会话(TCP 事件检测是纯函数,
  // 单次成本受性能护栏约束),命中证据链报文则直接定位到对应事件。
  const viewEventContext = useCallback(() => {
    if (!selected) return
    const facts = analyzeStream(selected.packets)
    const events = detectTcpEvents(facts, selected.packets)
    if (events.length === 0) {
      window.alert('该会话未检出可解释的 TCP 事件。')
      return
    }
    const pNum = useApp.getState().selectedPacket
    const found =
      pNum != null
        ? events.findIndex(
            (ev) =>
              ev.originalSegmentPacket === pNum ||
              ev.retransmissionPacket === pNum ||
              ev.recoveryAckPacket === pNum ||
              ev.duplicateAckPackets.includes(pNum),
          )
        : -1
    if (found > 0) setCompareEventIndex(found) // 下标 0 为默认值,无需设置
    setPendingResume(null)
    openCompare(selected.id)
  }, [openCompare, selected, setCompareEventIndex])

  // 对照页证据导出(口径:实际故障侧=证据;正常参考示意永不进入导出)
  const onExportCompare = useCallback(async () => {
    if (!selected || !compare?.vm || compare.eventIndex < 0) return
    try {
      const label = `${selected.client} ↔ ${selected.server}`
      const md = exportCompareReport({
        fileName: meta?.fileName ?? currentPath.split(/[\\/]/).pop() ?? 'capture.pcapng',
        conversationLabel: label,
        eventNo: compare.eventIndex + 1,
        eventTotal: compare.summaries.length,
        vm: compare.vm,
      })
      await saveText(defaultCompareReportName(label, compare.eventIndex + 1), md)
    } catch (err) {
      window.alert(err instanceof Error ? err.message : String(err))
    }
  }, [compare, currentPath, meta, selected])

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
              events={compare?.summaries}
              eventIndex={compare?.eventIndex}
              onSelectEvent={setCompareEventIndex}
              eventKey={compare?.eventIndex != null && compare.eventIndex >= 0 ? compare.summaries[compare.eventIndex]?.id : undefined}
              initialStageIndex={pendingResume && pendingResume.conversationId === compareFor ? pendingResume.stageIndex : undefined}
              onExport={onExportCompare}
              onSelectPacket={jumpToPacket}
              onBack={exitCompare}
            />
          </ErrorBoundary>
        </>
      ) : (
        <>
          <Toolbar zoom={zoom} setZoom={setZoom} onExport={onExport} onExportText={onExportText} hasConversation={!!selected} />
          {error && <div className="err">{error}</div>}
          {selected && (
            <div style={{ padding: '4px 12px 0', display: 'flex', gap: 8 }}>
              <button type="button" className="btn" onClick={() => openCompare(selected.id)} data-testid="fault-analyze-entry">
                ⚠ 故障分析(对照正常参考)
              </button>
              {/* 跳包后的返回入口:恢复离开时的事件与阶段(分镜粒度) */}
              {compareResume && compareResume.conversationId === selected.id && (
                <button
                  type="button"
                  className="btn sm resume-btn"
                  data-testid="fault-analyze-resume"
                  onClick={resumeFaultAnalysis}
                  title="回到离开时的故障事件与分析阶段"
                >
                  ↩ 返回故障分析{compareResume.eventIndex >= 0 ? `(事件 ${compareResume.eventIndex + 1}` : ''}
                  {compareResume.stageIndex >= 0 ? ` · 阶段 ${compareResume.stageIndex + 1})` : compareResume.eventIndex >= 0 ? ')' : ''}
                </button>
              )}
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
                  <PacketDetail onViewTcpEvents={viewEventContext} />
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
