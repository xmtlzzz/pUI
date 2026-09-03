import { useEffect, useRef, useState } from 'react'
import { useApp } from '../state/appStore'
import { isTauri } from '../bridge/tauri'

const EXAMPLES = ['http', 'dns', 'mixed', 'lossy', 'remote', 'dual-a', 'dual-b']

/** 抓包文件打开过滤器:与 tshark -r 实际支持的常见现网格式对齐(tshark 4.6.6 实测)。
 *  识别机制:tshark 按内容魔数识别格式,与扩展名无关(实测 .5vw 后缀的 5views
 *  正常读取);本清单只决定文件选择器里能看到哪些文件,扩展名仅是可见性提示。
 *  gzip(.gz)由 tshark 透明解压(.cap.gz/.pcapng.gz 实测均可)。
 *  实测可读:pcap(含 nsecpcap 纳秒变体)/pcapng/5views/netmon2/nettl/snoop/
 *  ngsniffer/commview;登记在册(Wireshark 家族读过滤器)但未构造样本验证:
 *  erf/btsnoop/dct2000/eyesdn/nstrace/observer/visual。 */
const CAPTURE_EXTENSIONS = [
  // 一线现网格式(全实测可读;识别按内容魔数,后缀仅为选择器可见性)
  'pcap', 'pcapng', 'cap', 'dmp', 'gz', // Wireshark/tcpdump 家族 + gzip 透明解压
  'nas', '5vw', // InfoVista 5View(实测)
  'bfr', 'cap1', // Microsoft NetMon 2.x(实测)
  'trc', 'trc0', 'trc1', // HP-UX nettl(实测)/ Sun snoop 惯例
  'snoop', // Sun snoop(实测)
  'ncf', 'ncfx', 'syc', // TamoSoft CommView(实测)
  'enc', 'lor', // Sniffer(Windows/DOS)(实测 ngsniffer)
  // Wireshark 家族读过滤器登记在册、按内容识别兜底(厂商设备导出)
  'erf', 'erp', // Endace ERF(读路径实测:tshark 解析出 ERF Provenance)
  'cch', 'cap2', // btsnoop(Symbian/Android HCI;合成文件实测可读)
  'out', // Catapult DCT2000
  'fdt', // EyeSDN
  'oreo', 'tr1', // NetScaler(nstrace 家族,常以 .cap 惯例导出)
  'xvf', // Viavi Observer(实测)
  'vis', // Visual Networks(实测)
  'rf5', // Tektronix K12xx
  'capdata', // Windows 网络诊断包络
]

/** 报告导出格式:md=Markdown 文件;docx=Word 文档;pdf=打印预览(WebView 打印存 PDF) */
export type ReportFormat = 'md' | 'docx' | 'pdf'

interface Props {
  zoom: number
  setZoom: (z: number) => void
  /** 导出 PNG 回调;缺省则不渲染该按钮(仅主视图时序场景在选中会话后提供) */
  onExport?: () => void
  /** 导出 SVG 矢量图回调;缺省则不渲染(评估空缺:PNG 栅格化之外的矢量格式) */
  onExportSvg?: () => void
  /** 导出分析报告回调(格式由 reportFormat 决定);缺省则不渲染(仅主视图提供,
   *  对照页的导出走 FaultCompare 的「导出报告/证据 JSON」) */
  onExportReport?: () => void
  /** 报告格式选择(受控) */
  reportFormat?: ReportFormat
  setReportFormat?: (f: ReportFormat) => void
  /** 「紧凑叙述」勾选:真实反映到报告时序章节(传给 exportTranscript 第二参) */
  compactTranscript?: boolean
  setCompactTranscript?: (v: boolean) => void
  /** 「仅异常包」勾选:时序章节只列带 ⚠ 分析标记的报文 */
  anomaliesOnly?: boolean
  setAnomaliesOnly?: (v: boolean) => void
  hasConversation: boolean
}

export function Toolbar({ zoom, setZoom, onExport, onExportSvg, onExportReport, reportFormat = 'md', setReportFormat, compactTranscript = false, setCompactTranscript, anomaliesOnly = false, setAnomaliesOnly, hasConversation }: Props) {
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
  const setTsharkPath = useApp((s) => s.setTsharkPath)
  const [tsharkErr, setTsharkErr] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // 解析引擎版本:应用启动后拉取一次,顶部信息条展示
  useEffect(() => {
    loadTsharkVersion()
  }, [loadTsharkVersion])

  // tshark 路径设置(Tauri:原生文件选择器选 tshark.exe;浏览器 dev:prompt 输入)。
  // Rust 侧 set_tshark_path 有强校验(绝对路径/exe/文件名含 tshark/非符号链接),
  // 校验失败会 reject,这里把错误展示给用户 —— 此前只有报错文案没有设置入口(断点)
  const setTsharkPathUi = async (): Promise<void> => {
    setTsharkErr(null)
    try {
      let path: string | null = null
      if (isTauri()) {
        const { open: openDialog } = await import('@tauri-apps/plugin-dialog')
        const picked = await openDialog({ multiple: false, filters: [{ name: 'tshark 可执行文件', extensions: ['exe'] }] })
        if (typeof picked === 'string') path = picked
      } else {
        path = window.prompt('输入 tshark 可执行文件的完整路径(如 C:\\Program Files\\Wireshark\\tshark.exe):')
      }
      if (path) await setTsharkPath(path)
    } catch (e) {
      setTsharkErr(e instanceof Error ? e.message : String(e))
    }
  }
  // 解析耗时标签(毫秒/秒),供信息条展示
  const parseMs = meta?.parseMs
  const parseMsLabel = parseMs != null && parseMs > 0 ? (parseMs < 1000 ? `${Math.round(parseMs)}ms` : `${(parseMs / 1000).toFixed(1)}s`) : null

  const pickFile = async () => {
    if (isTauri()) {
      // Tauri 2 不再向 <input type=file> 注入 File.path,须用原生对话框取真实路径
      const { open: openDialog } = await import('@tauri-apps/plugin-dialog')
      const path = await openDialog({
        multiple: false,
        filters: [{ name: '抓包文件(pcap/pcapng/cap/gzip 等,全格式)', extensions: CAPTURE_EXTENSIONS }],
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
          accept={CAPTURE_EXTENSIONS.map((e) => `.${e}`).join(',')}
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
        {/* tshark 路径设置:解析引擎全局配置,不依赖会话。此前只有报错文案
            「tshark not found: set its path in settings」却没有设置入口(断点),
            这里补上 —— Rust 侧 set_tshark_path 强校验,失败信息就地展示 */}
        <button className="btn icon" onClick={setTsharkPathUi} title={tsharkVersion ? `tshark ${tsharkVersion} · 点击更换路径` : '设置 tshark 路径(未检测到 tshark)'}>
          ⚙
        </button>
        {tsharkErr && <span className="meta err" title="tshark 路径校验失败">{tsharkErr}</span>}
        {hasConversation && (
          <>
            <div className="seg">
              <button className={diagramStyle === 'A' ? 'on' : ''} onClick={() => setDiagramStyle('A')}>
                A 斜线
              </button>
              <button className={diagramStyle === 'B' ? 'on' : ''} onClick={() => setDiagramStyle('B')}>
                B 行式
              </button>
              {/* C 序号空间:横向字节轴 + 缺口/SACK/ACK 游标(用户要求 2026-09-01,
                  要 FaultCompare 序列空间条带图的读法,不要报文交互箭头) */}
              <button className={diagramStyle === 'C' ? 'on' : ''} onClick={() => setDiagramStyle('C')}>
                C 序号空间
              </button>
              {/* D 时间流:纵轴时间逐行排布(2026-09-02 用户要求加回:内容多时
                  C 的横向字节轴难辨交互先后,D 每包一行从上往下看时间顺序) */}
              <button className={diagramStyle === 'D' ? 'on' : ''} onClick={() => setDiagramStyle('D')}>
                D 时间流
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
            {onExportSvg && (
              <button className="btn" onClick={onExportSvg} title="导出当前时序图为 SVG 矢量图(放大不糊,可进编辑器)">
                导出 SVG
              </button>
            )}
            {onExportReport && (
              <span className="toolbar-export">
                <label className="mini-check" title="报告时序章节:连续相同报文合并为 #X–#Y 区间,大幅减少重复行">
                  <input
                    type="checkbox"
                    checked={compactTranscript}
                    onChange={(e) => setCompactTranscript?.(e.target.checked)}
                  />
                  紧凑叙述
                </label>
                <label className="mini-check" title="报告时序章节:只列带 ⚠ 分析标记(重传/乱序/丢失/dup-ack 等)的报文,适合周报">
                  <input
                    type="checkbox"
                    checked={anomaliesOnly}
                    onChange={(e) => setAnomaliesOnly?.(e.target.checked)}
                  />
                  仅异常包
                </label>
                <select
                  className="btn"
                  value={reportFormat}
                  onChange={(e) => setReportFormat?.(e.target.value as ReportFormat)}
                  title="选择报告格式:Markdown / Word / PDF"
                  data-testid="report-format"
                >
                  <option value="md">Markdown (.md)</option>
                  <option value="docx">Word (.docx)</option>
                  <option value="pdf">PDF(打印预览)</option>
                </select>
                <button className="btn" onClick={onExportReport} title="导出当前会话的分析报告(概要/异常与发现/时序/证据口径)">
                  导出报告
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
