// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { createRef } from 'react'
import { SeqSpaceTimeline } from './SeqSpaceTimeline.tsx'
import { useApp } from '../state/appStore'
import type { Packet, Conversation } from '../model/types'

beforeEach(() => {
  useApp.setState({ seqSegIdx: null, seqSpaceWindows: {}, selectedPacket: null })
})

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

  it('占满容器宽度:容器比默认 720 宽时 viewBox 宽跟随容器(jsdom mock 1200)', () => {
    // jsdom 无真实布局,通过 mock getBoundingClientRect 驱动 ResizeObserver 路径
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const wrap = container.querySelector('.seq-wrap') as HTMLElement
    const svg = container.querySelector('svg')!
    // 初始:默认宽(布局 720)
    expect(svg.getAttribute('viewBox')!.split(' ')[2]).toBe('720')
    // 模拟容器加宽:ResizeObserver 回调
    wrap.getBoundingClientRect = () => ({ width: 1200 } as DOMRect)
    act(() => {
      window.dispatchEvent(new Event('resize'))
    })
    // 观察者触发后 viewBox 跟随 1200
    act(() => {
      ;(window as unknown as { __seqspResize?: () => void }).__seqspResize?.()
    })
    expect(svg.getAttribute('viewBox')!.split(' ')[2]).toBe('1200')
  })

  it('非 TCP 会话:渲染时间轴线条交互图,每报文一条可点击方向线段', () => {
    const ps = [
      pkt(1, { transport: 'icmp', proto: 'icmp', srcIp: 'a', dstIp: 'b', time: 0.1, direction: 'request' }),
      pkt(2, { transport: 'icmp', proto: 'icmp', srcIp: 'b', dstIp: 'a', time: 0.2, direction: 'response' }),
      pkt(3, { transport: 'icmp', proto: 'icmp', srcIp: 'a', dstIp: 'b', time: 0.5, direction: 'request' }),
    ]
    const onSelect = vi.fn()
    const { container } = render(<SeqSpaceTimeline conv={conv(ps)} onSelect={onSelect} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // 3 条方向线段(不是点点点)
    expect(svg.querySelectorAll('[data-testid="seqsp-msg"]')).toHaveLength(3)
    const lines = svg.querySelectorAll('[data-testid="seqsp-msg"] line')
    expect(lines.length).toBeGreaterThanOrEqual(3)
    // 轴说明是时间轴读法
    expect(svg.textContent).toContain('时间轴(相对秒)')
    // 点击线段回调帧号
    fireEvent.click(svg.querySelector('[data-pkt="2"]')!)
    expect(onSelect).toHaveBeenCalledWith(2)
  })

  it('TCP 会话:两行方向标注(客户端→ / 服务端→),一眼看出谁发谁收', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    expect(svg.textContent).toContain('客户端 →')
    expect(svg.textContent).toContain('服务端 →')
  })

  it('全轴状态滚轮不 preventDefault(容器可滚动);缩放生效后才拦截', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // 全轴(各带窗口均为 null):滚轮交还容器,不拦截默认滚动
    // (多带会话图高超过滚动容器时,指针在 svg 上必须还能上下滚动)
    const e1 = new WheelEvent('wheel', { deltaY: -100, bubbles: true, cancelable: true })
    act(() => {
      svg.dispatchEvent(e1)
    })
    expect(e1.defaultPrevented).toBe(false)
    // 缩放生效后(窗口非全轴):滚轮缩放拦截默认滚动,缩放不与容器滚动串动
    const e2 = new WheelEvent('wheel', { deltaY: -100, bubbles: true, cancelable: true })
    act(() => {
      svg.dispatchEvent(e2)
    })
    expect(e2.defaultPrevented).toBe(true)
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

  it('缩放窗口从 store 读取(阅读上下文跨形态保留)', () => {
    useApp.setState({ seqSpaceWindows: { 'tcp-c2s-0': { start: 0, end: 50 } } })
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    // store 里的窗口生效:带标题出现放大范围,且刻度轴按窗口重算(轴说明不再全轴)
    expect(svg.textContent).toContain('· 放大')
  })

  it('滚轮缩放写回 store.seqSpaceWindows(切形态后回到原缩放位置)', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    fireEvent.wheel(svg, { deltaY: -100 })
    // 缩放后的窗口已写入 store(至少一条带非全轴)
    expect(Object.values(useApp.getState().seqSpaceWindows).some((w) => w != null)).toBe(true)
  })

  it('双击复位清空 store 缩放窗口(全图回到全轴)', () => {
    useApp.setState({ seqSpaceWindows: { 'tcp-c2s-0': { start: 0, end: 50 } } })
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    const svg = container.querySelector('svg')!
    expect(svg.textContent).toContain('· 放大')
    fireEvent.dblClick(svg)
    expect(useApp.getState().seqSpaceWindows).toEqual({})
    expect(svg.textContent).not.toContain('· 放大')
  })

  it('分段导航接入 C:store.seqSegIdx 控制段内渲染,点击段按钮写回 store', () => {
    // 构造两段:前 4 包一段(time<1s),后 3 包一段(time>5s)
    const segPackets = packets.map((p, i) => ({ ...p, time: i < 4 ? i * 0.001 : 5 + (i - 4) * 0.001 }))
    const convSeg = conv(segPackets)
    const { container } = render(<SeqSpaceTimeline conv={convSeg} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    // 段按钮出现
    expect(container.querySelector('.seg-nav')).toBeTruthy()
    // 全部:ACK 301 可见(它在第 2 段,由包 6 携带)
    expect(container.textContent).toContain('累计确认 ACK 301')
    // 点击「1段」→ store.seqSegIdx=0,只渲染第 1 段(无 ACK 301)
    fireEvent.click(container.querySelectorAll('.seg-nav button')[1]!)
    expect(useApp.getState().seqSegIdx).toBe(0)
    expect(container.textContent).not.toContain('累计确认 ACK 301')
  })

  it('缩放到当前选中报文:store 选中报文 → 窗口平移到该报文 seq 附近', () => {
    const { container } = render(<SeqSpaceTimeline conv={conv(packets)} onSelect={() => {}} svgRef={createRef()} zoom={1} />)
    act(() => {
      useApp.setState({ selectedPacket: 3 }) // 包 3:seq=1 len=100(c2s 带)
    })
    const w = useApp.getState().seqSpaceWindows['tcp-c2s-0']
    expect(w).toBeTruthy()
    expect(w!.start).toBeLessThanOrEqual(1)
    expect(w!.end).toBeGreaterThanOrEqual(1)
    // 组件渲染出现放大范围
    expect(container.textContent).toContain('· 放大')
  })
})
