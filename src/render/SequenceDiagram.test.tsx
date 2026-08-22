// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, fireEvent } from '@testing-library/react'
import type { RefObject } from 'react'
import { SequenceDiagram } from './SequenceDiagram'
import type { Conversation, Packet } from '../model/types'

const packets: Packet[] = [
  { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', direction: 'request', info: 'TCP SYN' },
  { number: 2, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', direction: 'response', info: 'TCP SYN-ACK' },
  { number: 3, time: 0.05, len: 130, transport: 'tcp', proto: 'http', direction: 'request', info: 'HTTP GET /' },
]
const conv: Conversation = {
  id: 'k',
  client: '192.168.1.10:54321',
  server: '93.184.216.34:80',
  protocol: 'http',
  packetCount: 3,
  bytes: 250,
  start: 0,
  end: 0.05,
  duration: 0.05,
  packets,
  issues: [],
}

describe('SequenceDiagram', () => {
  const svgRef = { current: null } as RefObject<SVGSVGElement | null>

  it('renders one arrow group per packet', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(container.querySelectorAll('.msg')).toHaveLength(3)
  })

  it('emits onSelect with packet number on click', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    const g = container.querySelectorAll('.msg')[0] as Element
    fireEvent.click(g)
    expect(onSelect).toHaveBeenCalledWith(1)
  })

  it('zoom 缩放时同步盒尺寸(滚动区可达,下半图不消失)', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} svgRef={svgRef} zoom={3} />)
    const svg = container.querySelector('svg') as SVGSVGElement
    // 基准高 TOP(52)+3*30+20=162;盒尺寸必须按 zoom 放大,否则滚动容器只有 162px 高
    expect(Number(svg.getAttribute('height'))).toBeCloseTo(486)
    expect(Number(svg.getAttribute('width'))).toBeCloseTo(1560)
    // viewBox 保持未缩放,导出/坐标不受影响
    expect(svg.getAttribute('viewBox')).toBe('0 0 520 162')
  })

  it('hover 不重新计算布局(useMemo 缓存)', async () => {
    const layout = await import('./layout')
    const spy = vi.spyOn(layout, 'layoutSequence')
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    const callsBefore = spy.mock.calls.length
    fireEvent.mouseEnter(container.querySelector('.msg') as Element)
    fireEvent.mouseLeave(container.querySelector('.msg') as Element)
    expect(spy.mock.calls.length).toBe(callsBefore)
    spy.mockRestore()
  })

  it('absolute 模式显示绝对时间戳', () => {
    const onSelect = vi.fn()
    const convAbs = { ...conv, packets: [{ ...packets[0], time: 5, timeEpoch: 1590969600.5 }] }
    const { container } = render(<SequenceDiagram conv={convAbs} style="B" timeMode="absolute" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(container.textContent).toMatch(/\d{2}:\d{2}:\d{2}\.\d{3}/) // HH:MM:SS.mmm
  })

  it('>2000 报文自动抽稀渲染并标注,首尾保底', () => {
    const onSelect = vi.fn()
    const manyPackets: Packet[] = Array.from({ length: 5000 }, (_, i) => ({
      number: i + 1, time: i * 0.001, len: 60, transport: 'tcp', proto: 'tcp', direction: 'request', info: 'TCP',
    }))
    const convMany: Conversation = { ...conv, packets: manyPackets, packetCount: 5000, bytes: 300000 }
    const { container, getByText } = render(<SequenceDiagram conv={convMany} style="B" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    const msgs = container.querySelectorAll('.msg')
    expect(msgs.length).toBeLessThan(5000) // 抽稀:stride=3 → ~1667 行
    expect(msgs.length).toBeGreaterThan(1500)
    expect(getByText(/已抽稀/)).toBeTruthy()
    // 首尾保底:尾包 #5000 必须渲染
    expect(container.textContent).toContain('5000')
  })

  it('highlight 中的报文号带高亮样式', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" highlight={[2]} onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    const msgs = container.querySelectorAll('.msg')
    expect(msgs[1].getAttribute('class')).toContain('hl')
    expect(msgs[0].getAttribute('class')).not.toContain('hl')
  })

  it('relative 模式(默认)仍显示相对秒数', () => {
    const onSelect = vi.fn()
    const { container } = render(<SequenceDiagram conv={conv} style="B" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(container.textContent).toContain('0.000')
  })

  it('从空态切换到有会话时不抛 hook 数量错误(真实点击会话路径)', () => {
    const onSelect = vi.fn()
    // 首次渲染 conv=null(打开文件后未选中会话),随后 rerender 为真实会话
    const { rerender, container } = render(<SequenceDiagram conv={null} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(() => {
      rerender(<SequenceDiagram conv={conv} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    }).not.toThrow()
    expect(container.querySelectorAll('.msg').length).toBe(3)
  })

  it('从有会话切回空态再接新会话(切换文件路径)不抛错', () => {
    const onSelect = vi.fn()
    const { rerender } = render(<SequenceDiagram conv={conv} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(() => {
      rerender(<SequenceDiagram conv={null} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
      rerender(<SequenceDiagram conv={conv} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    }).not.toThrow()
  })

  it('renders an empty state when no conversation selected', () => {
    const onSelect = vi.fn()
    const { getByText } = render(<SequenceDiagram conv={null} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(getByText(/选择一个会话/)).toBeTruthy()
  })
})
