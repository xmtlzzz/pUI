// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { createRef } from 'react'
import { SeqSpaceTimeline } from './SeqSpaceTimeline.tsx'
import type { Packet, Conversation } from '../model/types'

function pkt(n: number, o: Partial<Packet>): Packet {
  return {
    number: n,
    time: n * 0.001,
    len: 60,
    transport: 'TCP',
    proto: 'tcp',
    ...o,
  } as Packet
}

function conv(packets: Packet[]): Conversation {
  return {
    key: 'k',
    client: '10.0.0.1:1000',
    server: '10.0.0.2:80',
    protocol: 'tcp',
    packetCount: packets.length,
    packets,
    issues: [],
  } as unknown as Conversation
}

/** 握手 → 数据(带缺口) → SACK → 恢复 的最小故事 */
const packets = [
  pkt(1, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 0, tcpAck: 0, tcpLen: 0, tcpFlags: '0x0002' }),
  pkt(2, { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1000, tcpSeq: 0, tcpAck: 1, tcpLen: 0, tcpFlags: '0x0012' }),
  pkt(3, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
  pkt(4, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
  pkt(5, { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1000, tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[201, 301]] }),
  pkt(6, { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1000, tcpSeq: 1, tcpAck: 301, tcpLen: 0 }),
  pkt(7, { srcIp: '10.0.0.1', srcPort: 1000, dstIp: '10.0.0.2', dstPort: 80, tcpSeq: 101, tcpAck: 301, tcpLen: 100 }),
]

describe('SeqSpaceTimeline', () => {
  it('空会话渲染空态', () => {
    render(<SeqSpaceTimeline conv={null} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    expect(screen.getByText('从左侧选择一个会话查看时序图')).toBeTruthy()
  })

  it('渲染两条方向带,带标题=端点对方向', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    expect(svg.textContent).toContain('10.0.0.1:1000 → 10.0.0.2:80')
    expect(svg.textContent).toContain('10.0.0.2:80 → 10.0.0.1:1000')
  })

  it('第二张图元素齐全:绿已收条/红斜纹缺口/紫SACK/蓝ACK游标', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // 绿色已见条(#10b981)
    expect(svg.querySelector('rect[fill="#10b981"]')).toBeTruthy()
    // 红斜纹缺口(pattern 引用)
    expect(svg.querySelector('rect[fill="url(#seqsp-hatch)"]')).toBeTruthy()
    // 紫色 SACK(#8b5cf6)
    expect(svg.querySelector('rect[fill="#8b5cf6"]')).toBeTruthy()
    // 蓝色 ACK 游标(#1d4ed8)+ 文本
    expect(svg.textContent).toContain('累计确认 ACK 301')
    // 轴说明
    expect(svg.textContent).toContain('序列号空间(字节)')
  })

  it('缺口 title 给出未收到字节范围;SACK title 给出对端已收范围', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    const gap = svg.querySelector('rect[fill="url(#seqsp-hatch)"]')!
    expect(gap.querySelector('title')?.textContent).toContain('未收到')
    expect(gap.querySelector('title')?.textContent).toContain('101')
    const sack = svg.querySelector('rect[fill="#8b5cf6"]')!
    expect(sack.querySelector('title')?.textContent).toContain('SACK')
  })

  it('重传报文画红色标记', () => {
    const ps = [
      pkt(1, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100 }),
      pkt(2, { srcIp: 'a', dstIp: 'b', tcpSeq: 0, tcpLen: 100, tcpAnalysis: ['retransmission'] }),
    ]
    const { container } = render(<SeqSpaceTimeline conv={conv(ps)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    expect(svg.querySelector('[data-testid="seqsp-retx"]')).toBeTruthy()
  })

  it('点击带内报文标记触发 onSelect(帧号)', () => {
    const onSelect = vi.fn()
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={onSelect} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    const hit = svg.querySelector('[data-pkt="7"]') as SVGElement
    expect(hit).toBeTruthy()
    fireEvent.click(hit)
    expect(onSelect).toHaveBeenCalledWith(7)
  })

  it('字节刻度渲染在带下方(数值文本)', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // c2s 带轴 0..301,1/2/5 步长必有刻度文本
    expect(svg.textContent).toMatch(/0/)
    expect(svg.querySelector('g[data-testid="seqsp-ticks"]')).toBeTruthy()
  })

  it('zoom 盒尺寸模式:width/height 乘 zoom', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={2} />)
    const svg = container.querySelector('svg')!
    const w = Number(svg.getAttribute('width'))
    const vbW = svg.getAttribute('viewBox')!.split(' ').map(Number)[2]
    expect(w).toBe(vbW * 2)
  })

  it('非 TCP 会话:渲染时间轴回退带,每报文一个可点击点', () => {
    const ps = [
      pkt(1, { transport: 'udp', proto: 'mdns', srcIp: 'a', dstIp: '224.0.0.251', srcPort: 5353, dstPort: 5353 }),
      pkt(2, { transport: 'arp', proto: 'arp', srcMac: 'aa', dstMac: 'ff', srcIp: 'a' }),
      pkt(3, { transport: 'udp', proto: 'mdns', srcIp: 'a', dstIp: '224.0.0.251', srcPort: 5353, dstPort: 5353 }),
    ]
    const onSelect = vi.fn()
    const { container } = render(<SeqSpaceTimeline conv={conv(ps)} onSelect={onSelect} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // 不再是空态:有 2 条回退带(mdns/arp),带内 3 个报文点
    expect(svg.querySelectorAll('[data-testid="seqsp-msg"]')).toHaveLength(3)
    // 轴说明是时间轴读法
    expect(svg.textContent).toContain('时间轴(报文序号)')
    // 点击报文点回调帧号
    fireEvent.click(svg.querySelector('[data-pkt="2"]')!)
    expect(onSelect).toHaveBeenCalledWith(2)
  })

  it('滚轮缩放:向上滚(放大)后带标题出现放大范围,双击复位', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // 初始无放大标记
    expect(svg.textContent).not.toContain('· 放大')
    // 滚轮向上(deltaY<0)= 放大
    fireEvent.wheel(svg, { deltaY: -100 })
    // 带标题出现「· 放大 <范围>」
    expect(svg.textContent).toContain('· 放大')
    // 双击复位
    fireEvent.dblClick(svg)
    expect(svg.textContent).not.toContain('· 放大')
  })

  it('拖拽平移:按下并水平移动后窗口平移(游标位置变化)', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    fireEvent.wheel(svg, { deltaY: -120 })
    const before = svg.textContent
    // 指针拖拽序列
    fireEvent.pointerDown(svg, { pointerId: 1, clientX: 400, clientY: 100, buttons: 1 })
    fireEvent.pointerMove(svg, { pointerId: 1, clientX: 200, clientY: 100 })
    fireEvent.pointerUp(svg, { pointerId: 1 })
    // 平移后文本应变化(刻度值范围移动)
    expect(svg.textContent).not.toBe(before)
  })
})
