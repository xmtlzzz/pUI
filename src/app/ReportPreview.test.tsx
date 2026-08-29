// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from 'vitest'
import { fireEvent, render, screen, cleanup } from '@testing-library/react'
import { ReportPreview } from './ReportPreview'

afterEach(cleanup)

describe('ReportPreview 打印预览(PDF 导出路径)', () => {
  it('渲染 iframe(srcDoc=报告 HTML)与顶栏操作;关闭按钮回调 onClose', () => {
    const onClose = vi.fn()
    render(<ReportPreview html="<html><body><h1>抓包分析报告</h1></body></html>" fileName="demo.pcapng" onClose={onClose} />)
    const overlay = screen.getByTestId('report-preview')
    expect(overlay.getAttribute('role')).toBe('dialog')
    const frame = overlay.querySelector('iframe')!
    expect(frame.getAttribute('srcdoc')).toContain('抓包分析报告')
    expect(screen.getByTestId('rp-print').textContent).toContain('打印')
    fireEvent.click(screen.getByTestId('rp-close'))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('Escape 键关闭预览(键盘可达)', () => {
    const onClose = vi.fn()
    render(<ReportPreview html="<p>x</p>" fileName="d" onClose={onClose} />)
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('打印按钮把 print 调用桥接到 iframe 内容窗口(WebView 打印 = 存 PDF)', () => {
    const { container } = render(<ReportPreview html="<p>x</p>" fileName="d" onClose={vi.fn()} />)
    const frame = container.querySelector('iframe')!
    const cw = frame.contentWindow as unknown as Record<string, unknown>
    const printSpy = vi.fn()
    cw.print = printSpy
    cw.focus = vi.fn()
    fireEvent.click(screen.getByTestId('rp-print'))
    expect(printSpy).toHaveBeenCalledOnce()
  })
})
