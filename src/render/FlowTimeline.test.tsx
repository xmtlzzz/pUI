// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { act } from 'react'
import { render, fireEvent } from '@testing-library/react'
import type { RefObject } from 'react'
import { FlowTimeline } from './FlowTimeline.tsx' // 显式扩展名:与 flowTimeline.ts 仅大小写之差(Win 大小写不敏感盘歧义)
import type { Conversation, Packet } from '../model/types'

const packets: Packet[] = [
  { number: 1, time: 0, len: 60, transport: 'tcp', proto: 'tcp', direction: 'request', info: 'TCP SYN' },
  { number: 2, time: 0.03, len: 60, transport: 'tcp', proto: 'tcp', direction: 'response', info: 'TCP SYN-ACK' },
  {
    number: 3,
    time: 0.05,
    len: 130,
    transport: 'tcp',
    proto: 'tcp',
    direction: 'request',
    info: 'TCP Retransmission',
    tcpAnalysis: ['retransmission'],
  },
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

function renderFlow(overrides: Partial<Parameters<typeof FlowTimeline>[0]> = {}) {
  const svgRef = { current: null } as RefObject<SVGSVGElement | null>
  const onSelect = vi.fn()
  const utils = render(
    <FlowTimeline conv={conv} onSelect={onSelect} svgRef={svgRef} zoom={1} {...overrides} />,
  )
  return { svgRef, onSelect, ...utils }
}

describe('FlowTimeline 时间流时序图', () => {
  it('渲染 svg[data-testid=flow-timeline],每个报文一行,行数正确', () => {
    const { container } = renderFlow()
    const svg = container.querySelector('svg[data-testid="flow-timeline"]')
    expect(svg).not.toBeNull()
    expect(container.querySelectorAll('.flow-row')).toHaveLength(3)
  })

  it('行点击触发 onSelect(帧号)', () => {
    const { container, onSelect } = renderFlow()
    fireEvent.click(container.querySelectorAll('.flow-row')[1])
    expect(onSelect).toHaveBeenCalledWith(2)
  })

  it('highlight 命中行带 hl 类名,未命中行不带', () => {
    const { container } = renderFlow({ highlight: [2] })
    const rows = container.querySelectorAll('.flow-row')
    expect(rows[1].getAttribute('class')).toContain('hl')
    expect(rows[0].getAttribute('class')).not.toContain('hl')
  })

  it('svgRef 挂载到 svg 元素(导出 PNG 依赖)', () => {
    const { svgRef, container } = renderFlow()
    expect(svgRef.current).not.toBeNull()
    expect(svgRef.current).toBe(container.querySelector('svg'))
  })

  it('zoom 乘盒尺寸(宽高放大,viewBox 不变;与 SequenceDiagram 盒尺寸模式一致)', () => {
    const { container } = renderFlow({ zoom: 2 })
    const svg = container.querySelector('svg') as SVGSVGElement
    const w = Number(svg.getAttribute('width'))
    const h = Number(svg.getAttribute('height'))
    const vw = Number(svg.getAttribute('viewBox')!.split(' ')[2])
    const vh = Number(svg.getAttribute('viewBox')!.split(' ')[3])
    expect(w).toBeCloseTo(vw * 2)
    expect(h).toBeCloseTo(vh * 2)
  })

  it('端点名标注在顶部,顶部为客户端、右侧为服务端', () => {
    const { container } = renderFlow()
    expect(container.textContent).toContain('192.168.1.10:54321')
    expect(container.textContent).toContain('93.184.216.34:80')
  })

  it('异常报文行带 anomaly 类(观察层强调,非结论)', () => {
    const { container } = renderFlow()
    const rows = container.querySelectorAll('.flow-row')
    expect(rows[2].getAttribute('class')).toContain('anomaly')
    expect(rows[0].getAttribute('class')).not.toContain('anomaly')
  })

  it('时间刻度列渲染每行时刻文本', () => {
    const { container } = renderFlow()
    expect(container.textContent).toContain('0.000')
    expect(container.textContent).toContain('0.030')
    expect(container.textContent).toContain('0.050')
  })

  it('request 行箭头向右(a2b),response 行箭头向左(b2a)', () => {
    const { container } = renderFlow()
    const rows = container.querySelectorAll('.flow-row')
    expect(rows[0].getAttribute('class')).toContain('a2b')
    expect(rows[1].getAttribute('class')).toContain('b2a')
  })

  it('conv 为 null 渲染空态,不抛错', () => {
    const onSelect = vi.fn()
    const svgRef = { current: null } as RefObject<SVGSVGElement | null>
    const { getByText } = render(<FlowTimeline conv={null} onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    expect(getByText(/选择一个会话/)).toBeTruthy()
  })

  it('超 2000 行截断渲染并显示提示(父层负责分段,组件兜底 DOM 上限)', () => {
    const many: Packet[] = Array.from({ length: 2600 }, (_, i) => ({
      number: i + 1,
      time: i * 0.001,
      len: 60,
      transport: 'tcp',
      proto: 'tcp',
      direction: 'request',
      info: 'TCP',
    }))
    const convMany: Conversation = { ...conv, packets: many, packetCount: 2600, bytes: 156000 }
    const onSelect = vi.fn()
    const svgRef = { current: null } as RefObject<SVGSVGElement | null>
    const { container, getByText } = render(
      <FlowTimeline conv={convMany} onSelect={onSelect} svgRef={svgRef} zoom={1} />,
    )
    const rows = container.querySelectorAll('.flow-row')
    expect(rows.length).toBeLessThanOrEqual(2000)
    // 步长采样(stride=ceil(2600/2000)=2 → 1300 行),首尾保底,与 SequenceDiagram 同策略
    expect(rows.length).toBeGreaterThan(1000)
    expect(getByText(/已截断/)).toBeTruthy()
    expect(container.textContent).toContain('2600')
  })

  it('total % stride === 1(采样恰好命中尾包)时不产生重复 key 的行', () => {
    // total=2501,stride=2 → 采样 i=0,2,...,2500 恰好命中最后一包;旧实现会把尾包
    // 追加两行 → 两个 .flow-row 同 packetNumber(React key 冲突 + 同包画两行)
    const many: Packet[] = Array.from({ length: 2501 }, (_, i) => ({
      number: i + 1,
      time: i * 0.001,
      len: 60,
      transport: 'tcp',
      proto: 'tcp',
      direction: 'request',
      info: 'TCP',
    }))
    const convMany: Conversation = { ...conv, packets: many, packetCount: 2501, bytes: 150060 }
    const onSelect = vi.fn()
    const svgRef = { current: null } as RefObject<SVGSVGElement | null>
    const { container } = render(<FlowTimeline conv={convMany} onSelect={onSelect} svgRef={svgRef} zoom={1} />)
    const rows = container.querySelectorAll('.flow-row')
    // 每行标注「#N 协议 · 长度」,抽帧号;渲染后帧号两两不同(无重复 React key)
    const nums = Array.from(rows, (r) => {
      const m = r.querySelector('.flow-label')?.textContent?.match(/#(\d+)/)
      return m ? Number(m[1]) : NaN
    })
    expect(new Set(nums).size).toBe(rows.length)
    // 尾包保底可见,且只画一次
    expect(nums.filter((n) => n === 2501)).toHaveLength(1)
  })

  it('占满容器宽度:容器比默认 520 宽时 viewBox 宽跟随容器(jsdom mock 1200)', () => {
    // jsdom 无真实布局,通过 mock getBoundingClientRect + resize/观察者钩子驱动
    const { container } = renderFlow()
    const wrap = container.querySelector('.seq-wrap') as HTMLElement
    const svg = container.querySelector('svg')!
    // 初始:默认宽(布局 520)
    expect(svg.getAttribute('viewBox')!.split(' ')[2]).toBe('520')
    // 模拟容器加宽
    wrap.getBoundingClientRect = () => ({ width: 1200 } as DOMRect)
    act(() => {
      window.dispatchEvent(new Event('resize'))
    })
    act(() => {
      ;(window as unknown as { __flowResize?: () => void }).__flowResize?.()
    })
    // viewBox 跟随 1200(整页板块不再右侧留白,与 C 形态同要求)
    expect(svg.getAttribute('viewBox')!.split(' ')[2]).toBe('1200')
  })
})
