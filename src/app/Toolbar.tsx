import { useRef } from 'react'
import { useApp } from '../state/appStore'
import { isTauri } from '../bridge/tauri'

const EXAMPLES = ['http', 'dns', 'mixed']

interface Props {
  zoom: number
  setZoom: (z: number) => void
  onExport: () => void
  hasConversation: boolean
}

export function Toolbar({ zoom, setZoom, onExport, hasConversation }: Props) {
  const meta = useApp((s) => s.meta)
  const openFile = useApp((s) => s.openFile)
  const openExample = useApp((s) => s.openExample)
  const loading = useApp((s) => s.loading)
  const diagramStyle = useApp((s) => s.diagramStyle)
  const setDiagramStyle = useApp((s) => s.setDiagramStyle)
  const inputRef = useRef<HTMLInputElement>(null)

  const pickFile = async () => {
    if (isTauri()) {
      // Tauri 2 不再向 <input type=file> 注入 File.path,须用原生对话框取真实路径
      const { open: openDialog } = await import('@tauri-apps/plugin-dialog')
      const path = await openDialog({
        multiple: false,
        filters: [{ name: '抓包文件 (pcap/pcapng)', extensions: ['pcap', 'pcapng', 'gz'] }],
      })
      if (typeof path === 'string') openFile(path)
    } else {
      inputRef.current?.click()
    }
  }

  return (
    <div className="toolbar">
      <div className="toolbar-left">
        <button className="btn primary" onClick={pickFile} disabled={loading}>
          📂 打开文件
        </button>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.gz"
          style={{ display: 'none' }}
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) openFile(f.name)
            e.target.value = ''
          }}
        />
        <select
          className="btn"
          defaultValue=""
          onChange={(e) => {
            if (e.target.value) openExample(e.target.value)
            e.target.value = ''
          }}
        >
          <option value="">打开示例…</option>
          {EXAMPLES.map((x) => (
            <option key={x} value={x}>
              {x}
            </option>
          ))}
        </select>
      </div>

      <div className="toolbar-center">
        {meta && !loading && (
          <span className="meta" key={meta.fileName}>
            {meta.fileName} · {meta.packetCount} 报文 · {meta.interfaces} 接口 · {meta.timeStart.toFixed(2)}~{meta.timeEnd.toFixed(2)}s · {fmt(meta.fileSize)}
          </span>
        )}
        {loading && <span className="meta pulse">解析中…</span>}
        {!meta && !loading && <span className="meta dim">打开抓包文件开始分析</span>}
      </div>

      <div className="toolbar-right">
        {hasConversation && (
          <>
            <div className="seg">
              <button className={diagramStyle === 'A' ? 'on' : ''} onClick={() => setDiagramStyle('A')}>
                A 斜线
              </button>
              <button className={diagramStyle === 'B' ? 'on' : ''} onClick={() => setDiagramStyle('B')}>
                B 行式
              </button>
            </div>
            <button className="btn icon" onClick={() => setZoom(Math.max(0.5, zoom - 0.1))} title="缩小">
              −
            </button>
            <span className="zoom-label">{Math.round(zoom * 100)}%</span>
            <button className="btn icon" onClick={() => setZoom(Math.min(3, zoom + 0.1))} title="放大">
              +
            </button>
            <button className="btn primary" onClick={onExport}>
              导出 PNG
            </button>
          </>
        )}
      </div>
    </div>
  )
}

function fmt(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${bytes}B`
}
