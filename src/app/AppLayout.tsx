import { useEffect, useRef, useState, type DragEvent, type MouseEvent } from 'react'
import { Toolbar } from './Toolbar'
import { FilterPanel } from './FilterPanel'
import { ConversationList } from './ConversationList'
import { SequenceDiagram } from '../render/SequenceDiagram'
import { PacketDetail } from '../detail/PacketDetail'
import { useApp, selectSelected } from '../state/appStore'
import { isTauri } from '../bridge/tauri'
import { exportSvgPng, defaultPngName } from '../export/exportPng'

function clamp(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v))
}

export function AppLayout() {
  const openFile = useApp((s) => s.openFile)
  const error = useApp((s) => s.error)
  const selected = useApp((s) => selectSelected(s))
  const diagramStyle = useApp((s) => s.diagramStyle)
  const selectPacket = useApp((s) => s.selectPacket)
  const [drag, setDrag] = useState(false)
  const [zoom, setZoom] = useState(1)
  const svgRef = useRef<SVGSVGElement | null>(null)

  // 可拖拽尺寸:会话列表宽度(左/右)、报文详情高度(上/下);持久化,拖一次即记住
  const LS_LIST = 'pui:listWidth'
  const LS_DETAIL = 'pui:detailHeight'
  const loadNum = (key: string, fallback: number): number => {
    const v = Number(localStorage.getItem(key))
    return Number.isFinite(v) && v > 0 ? v : fallback
  }
  const [listWidth, setListWidth] = useState(() => loadNum(LS_LIST, 380))
  const [detailHeight, setDetailHeight] = useState(() => loadNum(LS_DETAIL, 240))
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
    await exportSvgPng(svgRef.current, defaultPngName(selected.client, selected.server, selected.protocol))
  }

  // 会话列表宽度拖拽
  const startVDrag = (e: MouseEvent) => {
    e.preventDefault()
    const startX = e.clientX
    const initial = listRef.current
    const move = (ev: globalThis.MouseEvent) => {
      const w = clamp(initial + (ev.clientX - startX), 220, 720)
      listRef.current = w
      setListWidth(w)
    }
    const up = () => {
      document.removeEventListener('mousemove', move)
      document.removeEventListener('mouseup', up)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', move)
    document.addEventListener('mouseup', up)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }

  // 报文详情高度拖拽
  const startHDrag = (e: MouseEvent) => {
    e.preventDefault()
    const startY = e.clientY
    const initial = detailRef.current
    const move = (ev: globalThis.MouseEvent) => {
      const h = clamp(initial + (startY - ev.clientY), 90, Math.max(90, window.innerHeight - 220))
      detailRef.current = h
      setDetailHeight(h)
    }
    const up = () => {
      document.removeEventListener('mousemove', move)
      document.removeEventListener('mouseup', up)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', move)
    document.addEventListener('mouseup', up)
    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
  }

  // Tauri 2:拖拽文件须用窗口 onDragDropEvent 才能拿到真实路径
  useEffect(() => {
    if (!isTauri()) return
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
        unlisten = f
      })
    return () => unlisten?.()
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
      <Toolbar zoom={zoom} setZoom={setZoom} onExport={onExport} hasConversation={!!selected} />
      {error && <div className="err">{error}</div>}
      <div className="body">
        <div className="pane filter">
          <FilterPanel />
        </div>
        <div className="pane list" style={{ width: listWidth }}>
          <ConversationList />
        </div>
        <div className="v-resizer" onMouseDown={startVDrag} title="拖动调整宽度" />
        <div className="pane view">
          <SequenceDiagram conv={selected} style={diagramStyle} onSelect={selectPacket} svgRef={svgRef} zoom={zoom} />
          <div className="h-resizer" onMouseDown={startHDrag} title="拖动调整高度" />
          <div style={{ height: detailHeight, flex: 'none', overflow: 'hidden' }}>
            <PacketDetail />
          </div>
        </div>
      </div>
      {drag && <div className="drop-zone">松开以打开抓包文件</div>}
    </div>
  )
}
