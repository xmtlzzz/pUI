import { useRef } from 'react'
import { useApp } from '../state/appStore'

const EXAMPLES = ['http', 'dns', 'mixed']

export function Toolbar() {
  const meta = useApp((s) => s.meta)
  const openFile = useApp((s) => s.openFile)
  const openExample = useApp((s) => s.openExample)
  const loading = useApp((s) => s.loading)
  const inputRef = useRef<HTMLInputElement>(null)

  return (
    <div className="toolbar">
      <button className="btn primary" onClick={() => inputRef.current?.click()} disabled={loading}>
        📂 打开文件
      </button>
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng,.gz"
        style={{ display: 'none' }}
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) openFile((f as File & { path?: string }).path ?? f.name)
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
      <span className="spacer" />
      {meta && (
        <span className="meta">
          {meta.fileName} · {meta.packetCount} 报文 · {meta.interfaces} 接口 · {meta.timeStart.toFixed(2)}~{meta.timeEnd.toFixed(2)}s ·{' '}
          {fmt(meta.fileSize)}
        </span>
      )}
      {loading && <span className="meta">解析中…</span>}
    </div>
  )
}

function fmt(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${bytes}B`
}
