import { useEffect, useRef, useState } from 'react'
import { useApp } from '../state/appStore'
import { isTauri } from '../bridge/tauri'

const EXAMPLES = ['http', 'dns', 'mixed', 'lossy']

interface Props {
  zoom: number
  setZoom: (z: number) => void
  /** 导出 PNG 回调;缺省则不渲染该按钮(仅主视图时序场景在选中会话后提供) */
  onExport?: () => void
  /** 导出 Markdown 时序叙述回调;缺省则不渲染(仅主视图提供,对照页用对照报告导出) */
  onExportText?: () => void
  /** 「紧凑叙述」勾选:真实反映到导出内容(conflex 传给 exportTranscript 第二参) */
  compactTranscript?: boolean
  setCompactTranscript?: (v: boolean) => void
  /** 「仅异常包」勾选:只列带 ⚠ 分析标记的报文(第三参传给 exportTranscript) */
  anomaliesOnly?: boolean
  setAnomaliesOnly?: (v: boolean) => void
  hasConversation: boolean
}

export function Toolbar({ zoom, setZoom, onExport, onExportText, compactTranscript = false, setCompactTranscript, anomaliesOnly = false, setAnomaliesOnly, hasConversation }: Props) {
  const meta = useApp((s) => s.meta)
  const openFile = useApp((s) => s.openFile)
  const openExample = useApp((s) => s.openExample)
  const loading = useApp((s) => s.loading)
  const loadingFrames = useApp((s) => s.loadingFrames)
  const diagramStyle = useApp((s) => s.diagramStyle)
  const setDiagramStyle = useApp((s) => s.setDiagramStyle)
  const timeMode = useApp((s) => s.timeMode)
  const setTimeMode = useApp((s) => s.setTimeMode)
  const tsharkVersion = useApp((s) => s.tsharkVersion)
  const loadTsharkVersion = useApp((s) => s.loadTsharkVersion)
  const inputRef = useRef<HTMLInputElement>(null)

  // 解析引擎版本:应用启动后拉取一次,顶部信息条展示
  useEffect(() => {
    loadTsharkVersion()
  }, [loadTsharkVersion])
  // 解析耗时标签(毫秒/秒),供信息条展示
  const parseMs = meta?.parseMs
  const parseMsLabel = parseMs != null && parseMs > 0 ? (parseMs < 1000 ? `${Math.round(parseMs)}ms` : `${(parseMs / 1000).toFixed(1)}s`) : null

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
    // data-tauri-drag-region:无原生标题栏时,点击空白处可拖动窗口
    <div className="toolbar" data-tauri-drag-region>
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

      <div className="toolbar-center" data-tauri-drag-region>
        {meta && !loading && (
          <span className="meta" key={meta.fileName}>
            {meta.fileName} · {meta.packetCount} 报文 · {meta.interfaces} 接口 · {meta.timeStart.toFixed(2)}~{meta.timeEnd.toFixed(2)}s · {fmt(meta.fileSize)}
            {parseMsLabel && <> · 解析 {parseMsLabel}</>}
            {tsharkVersion && <> · tshark {tsharkVersion}</>}
          </span>
        )}
        {loading && <span className="meta pulse">解析中{loadingFrames > 0 ? `… 已解析 ${loadingFrames.toLocaleString()} 帧` : '…'}</span>}
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
            <div className="seg" title="相对:相对首包秒数;绝对:本地时钟时间戳(PRD F4)">
              <button className={timeMode === 'relative' ? 'on' : ''} onClick={() => setTimeMode('relative')}>
                相对
              </button>
              <button className={timeMode === 'absolute' ? 'on' : ''} onClick={() => setTimeMode('absolute')}>
                绝对
              </button>
            </div>
            <button className="btn icon" onClick={() => setZoom(Math.max(0.5, zoom - 0.1))} title="缩小">
              −
            </button>
            <span className="zoom-label">{Math.round(zoom * 100)}%</span>
            <button className="btn icon" onClick={() => setZoom(Math.min(3, zoom + 0.1))} title="放大">
              +
            </button>
            {onExport && (
              <button className="btn primary" onClick={onExport}>
                导出 PNG
              </button>
            )}
            {onExportText && (
              <span className="toolbar-export">
                <label className="mini-check" title="连续相同报文合并为 #X–#Y 区间,大幅减少重复行(typora 等打开巨大会话不卡顿)">
                  <input
                    type="checkbox"
                    checked={compactTranscript}
                    onChange={(e) => setCompactTranscript?.(e.target.checked)}
                  />
                  紧凑叙述
                </label>
                <label className="mini-check" title="只列带 ⚠ 分析标记(重传/乱序/丢失/dup-ack 等)的报文,丢掉正常握手/ACK,适合周报">
                  <input
                    type="checkbox"
                    checked={anomaliesOnly}
                    onChange={(e) => setAnomaliesOnly?.(e.target.checked)}
                  />
                  仅异常包
                </label>
                <button className="btn" onClick={onExportText} title="导出当前会话的 Markdown 时序叙述(可直接粘贴进文档/周报)">
                  导出叙述
                </button>
              </span>
            )}
          </>
        )}
        <WindowControls />
      </div>
    </div>
  )
}

/** 无原生标题栏时的自绘窗口控制(最小化/最大化/关闭),仅 Tauri 下渲染 */
function WindowControls() {
  const [max, setMax] = useState(false)
  const winOf = () => import('@tauri-apps/api/window').then((m) => m.getCurrentWindow())

  useEffect(() => {
    if (!isTauri()) return
    let disposed = false
    let un: (() => void) | undefined
    winOf().then(async (win) => {
      if (disposed) return
      un = await win.onResized(() => win.isMaximized().then(setMax))
      win.isMaximized().then(setMax)
    })
    return () => {
      disposed = true
      un?.()
    }
  }, [])

  if (!isTauri()) return null

  return (
    <div className="win-controls">
      <button className="wc" onClick={() => winOf().then((w) => w.minimize())} title="最小化">
        <svg width="10" height="10" viewBox="0 0 10 10"><path d="M1 5h8" stroke="currentColor" strokeWidth="1.2" /></svg>
      </button>
      <button
        className="wc"
        onClick={() => winOf().then(async (w) => { await w.toggleMaximize(); setMax(await w.isMaximized()) })}
        title={max ? '还原' : '最大化'}
      >
        <svg width="10" height="10" viewBox="0 0 10 10">
          {max ? <path d="M1.5 3.5h5v5h-5z M3.5 1.5h5v5" fill="none" stroke="currentColor" strokeWidth="1.2" /> : <rect x="1.2" y="1.2" width="7.6" height="7.6" rx="0.5" fill="none" stroke="currentColor" strokeWidth="1.2" />}
        </svg>
      </button>
      <button className="wc wc-close" onClick={() => winOf().then((w) => w.close())} title="关闭">
        <svg width="10" height="10" viewBox="0 0 10 10"><path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" strokeWidth="1.2" /></svg>
      </button>
    </div>
  )
}

function fmt(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${bytes}B`
}
