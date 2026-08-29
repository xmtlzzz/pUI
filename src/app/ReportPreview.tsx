import { useEffect, useRef } from 'react'

/**
 * 报告打印预览(PDF 导出路径):渲染报告 HTML 于 iframe,经由 WebView 原生打印
 * 生成 PDF(打印对话框里选「另存为 PDF / Microsoft Print to PDF」)。
 *
 * 为什么走打印而不是前端拼 PDF:程序化 PDF 要内嵌中文字体(数 MB 级)且排版能力弱;
 * WebView 打印用系统字体直接产出矢量中文 PDF,排版由报告 HTML 的打印 CSS 控制,
 * 离线可用、零额外依赖。用户先预览,再点「打印 / 保存为 PDF」弹出系统打印对话框。
 */
export function ReportPreview({ html, fileName, onClose }: { html: string; fileName: string; onClose: () => void }) {
  const frameRef = useRef<HTMLIFrameElement | null>(null)

  const print = (): void => {
    const win = frameRef.current?.contentWindow
    if (!win) return
    win.focus()
    try {
      win.print()
    } catch {
      /* 打印被环境拒绝(如无头测试)时静默:用户仍可手动触发 */
    }
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="rp-overlay" data-testid="report-preview" role="dialog" aria-modal="true" aria-label={`报告预览 · ${fileName}`}>
      <div className="rp-bar">
        <span className="rp-title">报告预览 · {fileName}</span>
        <span className="rp-hint">在打印对话框选择「另存为 PDF / Microsoft Print to PDF」保存 PDF 文件</span>
        <span className="rp-actions">
          <button type="button" className="btn primary" onClick={print} data-testid="rp-print" title="打开打印对话框(可另存为 PDF)">
            打印 / 保存为 PDF
          </button>
          <button type="button" className="btn" onClick={onClose} data-testid="rp-close">
            关闭
          </button>
        </span>
      </div>
      {/* sandbox 空串:报告是自包含静态 HTML(无脚本),收紧 iframe 能力面 */}
      <iframe ref={frameRef} title="报告预览" className="rp-frame" srcDoc={html} sandbox="" />
    </div>
  )
}
