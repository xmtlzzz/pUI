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

  it('renders an empty state when no conversation selected', () => {
    const onSelect = vi.fn()
    const { getByText } = render(<SequenceDiagram conv={null} style="A" onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(getByText(/选择一个会话/)).toBeTruthy()
  })
})
