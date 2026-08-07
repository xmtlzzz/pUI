import { useEffect, useState, type DragEvent } from 'react'
import { Toolbar } from './Toolbar'
import { FilterPanel } from './FilterPanel'
import { ConversationList } from './ConversationList'
import { SequenceDiagram } from '../render/SequenceDiagram'
import { PacketDetail } from '../detail/PacketDetail'
import { useApp, selectSelected } from '../state/appStore'
import { isTauri } from '../bridge/tauri'

export function AppLayout() {
  const openFile = useApp((s) => s.openFile)
  const error = useApp((s) => s.error)
  const selected = useApp((s) => selectSelected(s))
  const diagramStyle = useApp((s) => s.diagramStyle)
  const selectPacket = useApp((s) => s.selectPacket)
  const [drag, setDrag] = useState(false)

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
      <Toolbar />
      {error && <div className="err">{error}</div>}
      <div className="body">
        <div className="pane filter">
          <FilterPanel />
        </div>
        <div className="pane list">
          <ConversationList />
        </div>
        <div className="pane view">
          <SequenceDiagram conv={selected} style={diagramStyle} onSelect={selectPacket} />
          <PacketDetail />
        </div>
      </div>
      {drag && <div className="drop-zone">松开以打开抓包文件</div>}
    </div>
  )
}
