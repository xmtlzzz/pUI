import { useState, type DragEvent } from 'react'
import { Toolbar } from './Toolbar'
import { FilterPanel } from './FilterPanel'
import { ConversationList } from './ConversationList'
import { SequenceDiagram } from '../render/SequenceDiagram'
import { PacketDetail } from '../detail/PacketDetail'
import { useApp, selectSelected } from '../state/appStore'

export function AppLayout() {
  const openFile = useApp((s) => s.openFile)
  const error = useApp((s) => s.error)
  const selected = useApp((s) => selectSelected(s))
  const diagramStyle = useApp((s) => s.diagramStyle)
  const selectPacket = useApp((s) => s.selectPacket)
  const [drag, setDrag] = useState(false)

  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setDrag(false)
    const f = e.dataTransfer.files?.[0]
    if (f) openFile((f as File & { path?: string }).path ?? f.name)
  }

  return (
    <div
      className="app"
      onDragOver={(e) => {
        e.preventDefault()
        setDrag(true)
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
